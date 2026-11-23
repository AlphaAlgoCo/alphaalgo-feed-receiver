"""Unit tests for the `--doctor` configuration check and CI workflow."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from alphaalgo_receiver import generate_signing_secret
from alphaalgo_receiver.doctor import (
    format_doctor_report,
    parse_signing_keys_json,
    run_doctor,
)


class TestDoctor(unittest.TestCase):
    def setUp(self) -> None:
        self.secret_v1 = generate_signing_secret()
        self.secret_v2 = generate_signing_secret()
        self.tg_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
        self.discord_url = "https://discord.com/api/webhooks/123456/secretTok"

    def test_parse_signing_keys_json_errors(self) -> None:
        for bad in ("", "not-json", "[]", "{}"):
            with self.assertRaises(ValueError):
                parse_signing_keys_json(bad)

    def test_doctor_happy_path_redacts_all_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "nested" / "receipts.db")
            jsonl_path = str(Path(tmpdir) / "logs" / "events.jsonl")
            raw_keys = json.dumps(
                {"v1": self.secret_v1, "v2": self.secret_v2}
            )
            results = run_doctor(
                raw_keys_json=raw_keys,
                database=db_path,
                port=9091,
                jsonl_log=jsonl_path,
                discord_webhook=self.discord_url,
                telegram_bot_token=self.tg_token,
                telegram_chat_id="-1001234567890",
                check_clock=True,
                local_clock=lambda: 1_795_000_000.0,
                remote_clock=lambda _url: 1_795_000_002.5,
            )
            self.assertTrue(all(r.ok for r in results))
            # Temporary probe DB should not leave an empty file behind.
            self.assertFalse(Path(db_path).exists())

            report = format_doctor_report(results)
            self.assertIn("v1, v2", report)
            self.assertIn("Result: READY", report)
            # Secrets must never appear anywhere in the doctor output.
            self.assertNotIn(self.secret_v1, report)
            self.assertNotIn(self.secret_v2, report)
            self.assertNotIn("whsec_", report)
            self.assertNotIn(self.tg_token, report)
            self.assertNotIn("secretTok", report)

    def test_doctor_detects_bad_keys_port_and_sinks(self) -> None:
        results = run_doctor(
            raw_keys_json='{"v1":"invalid_secret"}',
            database=":memory:",
            port=70000,
            discord_webhook="http://evil.example.com/hook",
            telegram_bot_token=self.tg_token,
            telegram_chat_id="",
            check_clock=False,
        )
        by_name = {r.name: r for r in results}
        self.assertFalse(by_name["signing_keys"].ok)
        self.assertFalse(by_name["port"].ok)
        self.assertFalse(by_name["discord_sink"].ok)
        self.assertFalse(by_name["telegram_sink"].ok)
        self.assertNotIn("clock_skew", by_name)

        report = format_doctor_report(results)
        self.assertIn("Result: FAILED", report)

    def test_doctor_clock_skew_warn_fail_and_offline(self) -> None:
        raw_keys = json.dumps({"v1": self.secret_v1})

        # 120s skew -> WARN (ok=True, warning=True).
        warn_res = run_doctor(
            raw_keys_json=raw_keys,
            database=":memory:",
            port=9091,
            local_clock=lambda: 1_795_000_120.0,
            remote_clock=lambda _url: 1_795_000_000.0,
        )
        warn_clock = next(r for r in warn_res if r.name == "clock_skew")
        self.assertTrue(warn_clock.ok)
        self.assertTrue(warn_clock.warning)

        # 290s skew -> FAIL.
        fail_res = run_doctor(
            raw_keys_json=raw_keys,
            database=":memory:",
            port=9091,
            local_clock=lambda: 1_795_000_290.0,
            remote_clock=lambda _url: 1_795_000_000.0,
        )
        fail_clock = next(r for r in fail_res if r.name == "clock_skew")
        self.assertFalse(fail_clock.ok)

        # Unreachable remote -> graceful WARN, never hard fail.
        def _offline(_url: str) -> float:
            raise OSError("network unreachable")

        off_res = run_doctor(
            raw_keys_json=raw_keys,
            database=":memory:",
            port=9091,
            local_clock=lambda: 1_795_000_000.0,
            remote_clock=_offline,
        )
        off_clock = next(r for r in off_res if r.name == "clock_skew")
        self.assertTrue(off_clock.ok)
        self.assertTrue(off_clock.warning)

    def test_ci_workflow_file_present(self) -> None:
        root = Path(__file__).resolve().parents[1]
        ci = (root / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("unittest discover", ci)
        self.assertIn("--doctor --skip-clock-check", ci)


if __name__ == "__main__":
    unittest.main()
