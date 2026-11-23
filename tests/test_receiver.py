"""Unit tests for security verification, receiver HTTP/SQLite, and handlers."""
from __future__ import annotations

import base64
import io
import json
import math
import os
from pathlib import Path
import stat
import tempfile
import unittest

from alphaalgo_receiver import (
    FeedSecurityError,
    WebhookReceiver,
    discord_webhook_handler,
    dispatch_handlers,
    format_event_summary,
    generate_signing_secret,
    jsonl_file_handler,
    sign_event,
    validate_signing_keys,
    verify_event,
)
from alphaalgo_receiver.handlers import _build_discord_payload
from scripts.send_mock_event import build_mock_event


def _make_event(event_id: str = "aa3-test-001", **overrides) -> bytes:
    """Serialize a minimal valid v3 event envelope to canonical JSON bytes."""
    payload = {
        "schema_version": 3,
        "event_id": event_id,
        "trade_ref": "TR-1001",
        "trade_revision": 1,
        "event_kind": "entry",
        "record_kind": "fill",
        "strategy_id": "S608",
        "ticker": "AAPL",
        "option_symbol": "AAPL261218C00250000",
        "position_scale_x": 1.0,
        "entry_price": 3.50,
    }
    payload.update(overrides)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


class TestSecurity(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = generate_signing_secret()
        self.now = 1_795_000_000.0
        self.body = _make_event("aa3-sec-1")

    def test_generate_signing_secret_format(self) -> None:
        self.assertTrue(self.secret.startswith("whsec_"))
        raw = base64.b64decode(self.secret[6:], validate=True)
        self.assertGreaterEqual(len(raw), 32)

    def test_validate_signing_keys_rejects_bad_entries(self) -> None:
        with self.assertRaises(ValueError):
            validate_signing_keys({})
        with self.assertRaises(FeedSecurityError):
            validate_signing_keys({"v1": "not_a_whsec"})
        with self.assertRaises(FeedSecurityError):
            validate_signing_keys({"bad key": self.secret})

    def test_sign_event_validation_errors(self) -> None:
        bad_cases = [
            ("", 100, b"{}", self.secret, "v1"),
            ("bad id", 100, b"{}", self.secret, "v1"),
            ("aa3-1", -1, b"{}", self.secret, "v1"),
            ("aa3-1", True, b"{}", self.secret, "v1"),
            ("aa3-1", 100, "not-bytes", self.secret, "v1"),
            ("aa3-1", 100, b"{}", "not-whsec", "v1"),
            ("aa3-1", 100, b"{}", "whsec_short", "v1"),
            ("aa3-1", 100, b"{}", b"too-short", "v1"),
            ("aa3-1", 100, b"{}", self.secret, "bad key"),
        ]
        for args in bad_cases:
            with self.assertRaises(FeedSecurityError):
                sign_event(*args)  # type: ignore[arg-type]

    def test_verify_event_rejects_duplicate_headers(self) -> None:
        headers = sign_event(
            "aa3-sec-1", int(self.now), self.body, self.secret
        )
        headers["webhook-id"] = "aa3-sec-1"  # Duplicate with different case.
        with self.assertRaises(FeedSecurityError):
            verify_event(
                self.body, headers, {"v1": self.secret}, now=self.now
            )

    def test_verify_event_rejects_future_and_past_stale_timestamps(
        self,
    ) -> None:
        for delta in (-301, 301):
            headers = sign_event(
                "aa3-sec-1", int(self.now) + delta, self.body, self.secret
            )
            with self.assertRaises(FeedSecurityError):
                verify_event(
                    self.body, headers, {"v1": self.secret}, now=self.now
                )

    def test_verify_event_rejects_unknown_key_and_bad_timestamp(self) -> None:
        headers = sign_event(
            "aa3-sec-1", int(self.now), self.body, self.secret, key_id="v99"
        )
        with self.assertRaises(FeedSecurityError):
            verify_event(
                self.body, headers, {"v1": self.secret}, now=self.now
            )

        bad_ts = dict(headers, **{"Webhook-Timestamp": "not-a-number"})
        with self.assertRaises(FeedSecurityError):
            verify_event(
                self.body, bad_ts, {"v99": self.secret}, now=self.now
            )

    def test_verify_event_consume_callback(self) -> None:
        headers = sign_event(
            "aa3-sec-1", int(self.now), self.body, self.secret
        )
        seen: set[str] = set()

        def consume(eid: str) -> bool:
            if eid in seen:
                return False
            seen.add(eid)
            return True

        eid = verify_event(
            self.body,
            headers,
            {"v1": self.secret},
            now=self.now,
            consume=consume,
        )
        self.assertEqual(eid, "aa3-sec-1")
        with self.assertRaises(FeedSecurityError):
            verify_event(
                self.body,
                headers,
                {"v1": self.secret},
                now=self.now,
                consume=consume,
            )


class TestWebhookReceiver(unittest.TestCase):
    def setUp(self) -> None:
        self.secret_v1 = generate_signing_secret()
        self.secret_v2 = generate_signing_secret()
        self.now = 1_795_000_000.0
        self.seen: list[dict] = []
        self.receiver = WebhookReceiver(
            ":memory:",
            {"v1": self.secret_v1, "v2": self.secret_v2},
            on_event=self.seen.append,
            clock=lambda: self.now,
        )

    def tearDown(self) -> None:
        self.receiver.close()

    def _wsgi_call(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        *,
        content_type: str = "application/json",
        content_length: str | None = None,
        extra_environ: dict[str, str] | None = None,
    ) -> tuple[int, dict]:
        environ: dict[str, object] = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": (
                str(len(body)) if content_length is None else content_length
            ),
            "CONTENT_TYPE": content_type,
            "wsgi.input": io.BytesIO(body),
        }
        for key, val in (headers or {}).items():
            environ["HTTP_" + key.upper().replace("-", "_")] = val
        if extra_environ:
            environ.update(extra_environ)

        captured: dict[str, object] = {}

        def start_response(status, resp_headers):
            captured["status"] = int(status.split(" ", 1)[0])
            captured["headers"] = dict(resp_headers)

        chunks = self.receiver(environ, start_response)
        return int(captured["status"]), json.loads(
            b"".join(chunks).decode("utf-8")
        )

    def test_empty_or_malformed_keys_rejected_at_startup(self) -> None:
        with self.assertRaises(ValueError):
            WebhookReceiver(":memory:", {})
        with self.assertRaises(FeedSecurityError):
            WebhookReceiver(":memory:", {"v1": "whsec_invalid"})

    def test_healthz_and_not_found(self) -> None:
        status, body = self._wsgi_call("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["execution"], "disabled")
        self.assertEqual(body["schema_version"], 3)

        status404, body404 = self._wsgi_call("GET", "/unknown")
        self.assertEqual(status404, 404)
        self.assertEqual(body404["error"], "route_not_found")

    def test_valid_event_and_idempotent_duplicate(self) -> None:
        body = _make_event("aa3-evt-1")
        headers = sign_event(
            "aa3-evt-1", int(self.now), body, self.secret_v1, key_id="v1"
        )

        status1, res1 = self._wsgi_call("POST", "/events", body, headers)
        self.assertEqual(status1, 200)
        self.assertEqual(
            res1,
            {"accepted": True, "duplicate": False, "execution": "disabled"},
        )
        self.assertEqual(len(self.seen), 1)

        # Exact retry must return 200 duplicate=True without re-firing hook.
        status2, res2 = self._wsgi_call("POST", "/events", body, headers)
        self.assertEqual(status2, 200)
        self.assertEqual(
            res2,
            {"accepted": True, "duplicate": True, "execution": "disabled"},
        )
        self.assertEqual(len(self.seen), 1)

    def test_event_id_collision_returns_409(self) -> None:
        body1 = _make_event("aa3-collision", entry_price=3.50)
        h1 = sign_event(
            "aa3-collision", int(self.now), body1, self.secret_v1
        )
        self.assertEqual(self._wsgi_call("POST", "/events", body1, h1)[0], 200)

        body2 = _make_event("aa3-collision", entry_price=9.99)
        h2 = sign_event(
            "aa3-collision", int(self.now), body2, self.secret_v1
        )
        status, res = self._wsgi_call("POST", "/events", body2, h2)
        self.assertEqual(status, 409)
        self.assertEqual(res["error"], "event_id_collision")

    def test_tampered_body_and_stale_timestamp_401(self) -> None:
        body = _make_event("aa3-tamper")
        headers = sign_event(
            "aa3-tamper", int(self.now), body, self.secret_v1
        )
        tampered = body.replace(b"3.5", b"9.5")
        status, res = self._wsgi_call("POST", "/events", tampered, headers)
        self.assertEqual(status, 401)
        self.assertEqual(res["error"], "signature_rejected")

        stale_h = sign_event(
            "aa3-tamper", int(self.now) - 301, body, self.secret_v1
        )
        self.assertEqual(
            self._wsgi_call("POST", "/events", body, stale_h)[0], 401
        )

    def test_key_rotation_and_multiple_signatures(self) -> None:
        body = _make_event("aa3-rot")
        headers = sign_event(
            "aa3-rot", int(self.now), body, self.secret_v2, key_id="v2"
        )
        headers["Webhook-Signature"] = (
            "v1,invalidSig== " + headers["Webhook-Signature"]
        )
        status, res = self._wsgi_call("POST", "/events", body, headers)
        self.assertEqual(status, 200)
        self.assertFalse(res["duplicate"])

    def test_envelope_json_nan_and_http_bounds_rejected_400(self) -> None:
        # Wrong schema_version (including float 3.0).
        for bad_sv in (2, 3.0):
            bad_ver = _make_event("aa3-bad-schema", schema_version=bad_sv)
            h_ver = sign_event(
                "aa3-bad-schema", int(self.now), bad_ver, self.secret_v1
            )
            self.assertEqual(
                self._wsgi_call("POST", "/events", bad_ver, h_ver)[0], 400
            )

        # Non-standard JSON NaN constant rejected.
        nan_body = (
            b'{"event_id":"aa3-nan","schema_version":3,"entry_price":NaN}'
        )
        h_nan = sign_event(
            "aa3-nan", int(self.now), nan_body, self.secret_v1
        )
        self.assertEqual(self.receiver.receive(nan_body, h_nan)[0], 400)

        # Oversized direct receive() call rejected.
        self.assertEqual(self.receiver.receive(b"x" * 70000, {})[0], 400)

        # Mismatched body event_id vs Webhook-Id.
        mismatch = _make_event("aa3-body-id")
        h_mis = sign_event(
            "aa3-header-id", int(self.now), mismatch, self.secret_v1
        )
        self.assertEqual(
            self._wsgi_call("POST", "/events", mismatch, h_mis)[0], 400
        )

        # Wrong Content-Type, oversized length, chunked, truncated body.
        ok_body = _make_event("aa3-ct")
        h_ct = sign_event("aa3-ct", int(self.now), ok_body, self.secret_v1)
        self.assertEqual(
            self._wsgi_call(
                "POST", "/events", ok_body, h_ct, content_type="text/plain"
            )[0],
            400,
        )
        self.assertEqual(
            self._wsgi_call(
                "POST", "/events", ok_body, h_ct, content_length="70000"
            )[0],
            400,
        )
        self.assertEqual(
            self._wsgi_call(
                "POST",
                "/events",
                ok_body,
                h_ct,
                extra_environ={"HTTP_TRANSFER_ENCODING": "chunked"},
            )[0],
            400,
        )
        self.assertEqual(
            self._wsgi_call(
                "POST",
                "/events",
                ok_body[:-5],
                h_ct,
                content_length=str(len(ok_body)),
            )[0],
            400,
        )

    def test_hook_exception_does_not_fail_persisted_receipt(self) -> None:
        def boom(_event: dict) -> None:
            raise RuntimeError("downstream boom")

        rec = WebhookReceiver(
            ":memory:",
            {"v1": self.secret_v1},
            on_event=boom,
            clock=lambda: self.now,
        )
        try:
            body = _make_event("aa3-boom")
            headers = sign_event(
                "aa3-boom", int(self.now), body, self.secret_v1
            )
            with self.assertLogs("alphaalgo_receiver", level="ERROR"):
                status, res = rec.receive(body, headers)
            self.assertEqual(status, 200)
            self.assertFalse(res["duplicate"])
        finally:
            rec.close()

    def test_file_database_permissions_and_mock_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "receipts.db"
            rec = WebhookReceiver(
                db_path,
                {"v1": self.secret_v1},
                on_event=None,
                clock=lambda: self.now,
            )
            try:
                mode = stat.S_IMODE(os.stat(db_path).st_mode)
                self.assertEqual(mode, 0o600)

                eq = build_mock_event("equity_entry", self.now)
                self.assertEqual(eq["instrument"]["descriptor_version"], 1)
                self.assertEqual(eq["instrument"]["kind"], "single_option")
                self.assertTrue(eq["instrument"]["complete"])
                self.assertEqual(len(eq["instrument"]["legs"]), 1)
                self.assertEqual(
                    eq["option_symbol"],
                    eq["instrument"]["legs"][0]["option_symbol"],
                )

                spx = build_mock_event("spx_spread_entry", self.now)
                self.assertEqual(
                    spx["instrument"]["kind"], "vertical_credit_spread"
                )
                self.assertEqual(spx["instrument"]["structure"], "CPS")
                self.assertEqual(len(spx["instrument"]["legs"]), 2)
                self.assertIsNone(spx["option_symbol"])

                ibf = build_mock_event("spx_ibf_entry", self.now)
                self.assertEqual(ibf["instrument"]["kind"], "iron_butterfly")
                self.assertEqual(ibf["instrument"]["structure"], "IBF")
                self.assertEqual(len(ibf["instrument"]["legs"]), 4)
                self.assertIsNone(ibf["option_symbol"])

                for ev in (eq, spx, ibf):
                    self.assertNotIn("execution_eligible", ev)
                    self.assertNotIn("execution_block_reason", ev)
                    self.assertTrue(ev["fill_time_verified"])
                    raw = json.dumps(
                        ev, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                    hdrs = sign_event(
                        ev["event_id"], int(self.now), raw, self.secret_v1
                    )
                    status, res = rec.receive(raw, hdrs)
                    self.assertEqual(status, 200)
                    self.assertTrue(res["accepted"])
            finally:
                rec.close()


class TestHandlers(unittest.TestCase):
    def test_format_event_summary_fields_and_non_finite_guards(self) -> None:
        summary = format_event_summary(
            {
                "event_kind": "exit",
                "strategy_id": "S623",
                "trade_ref": "TR-42",
                "ticker": "SPX",
                "option_symbol": "SPXW261123P06000000",
                "position_scale_x": 0.75,
                "entry_price": 2.40,
                "exit_fill_price": 1.10,
                "cumulative_return_pct": 54.17,
            }
        )
        self.assertIn("[EXIT]", summary)
        self.assertIn("S623", summary)
        self.assertIn("#TR-42", summary)
        self.assertIn("scale=0.75x", summary)
        self.assertIn("entry=2.40", summary)
        self.assertIn("exit=1.10", summary)
        self.assertIn("ret=+54.17%", summary)

        # Bool and NaN values must not be formatted as numbers.
        weird = format_event_summary(
            {
                "position_scale_x": True,
                "entry_price": math.nan,
                "exit_fill_price": math.inf,
                "cumulative_return_pct": False,
            }
        )
        self.assertIn("scale=-", weird)
        self.assertNotIn("entry=", weird)
        self.assertNotIn("exit=", weird)
        self.assertNotIn("ret=", weird)

        # Multi-leg events with option_symbol=None format cleanly.
        ibf_summary = format_event_summary(
            build_mock_event("spx_ibf_entry", 1_795_000_000.0)
        )
        self.assertIn("IBF(4-leg)", ibf_summary)
        self.assertIn("S662", ibf_summary)

    def test_jsonl_file_handler_permissions_and_dispatch_isolation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "nested" / "events.jsonl"
            captured: list[str] = []

            def broken(_event: dict) -> None:
                raise RuntimeError("first handler failed")

            pipeline = dispatch_handlers(
                [
                    broken,
                    jsonl_file_handler(log_path),
                    lambda e: captured.append(e["event_id"]),
                ]
            )
            with self.assertLogs("alphaalgo_receiver.handlers", level="ERROR"):
                pipeline({"event_id": "aa3-h1", "strategy_id": "S608"})

            self.assertEqual(captured, ["aa3-h1"])
            mode = stat.S_IMODE(os.stat(log_path).st_mode)
            self.assertEqual(mode, 0o600)
            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["event_id"], "aa3-h1")

    def test_discord_url_validation_and_mention_sanitization(self) -> None:
        bad_urls = [
            "http://discord.com/api/webhooks/123/abc",
            "https://evil.example.com/api/webhooks/123/abc",
            "https://discord.com/not-a-webhook",
            "https://user:pass@discord.com/api/webhooks/123/abc",
        ]
        for url in bad_urls:
            with self.assertRaises(ValueError):
                discord_webhook_handler(url)

        # Valid Discord webhook URL accepted.
        handler = discord_webhook_handler(
            "https://discord.com/api/webhooks/123456/token"
        )
        self.assertTrue(callable(handler))

        # Backticks/newlines neutralized and mentions disabled.
        payload = json.loads(
            _build_discord_payload({"trade_ref": "x`\n@everyone"}).decode(
                "utf-8"
            )
        )
        self.assertEqual(payload["allowed_mentions"], {"parse": []})
        self.assertNotIn("\n", payload["content"])
        self.assertEqual(payload["content"].count("`"), 2)


if __name__ == "__main__":
    unittest.main()
