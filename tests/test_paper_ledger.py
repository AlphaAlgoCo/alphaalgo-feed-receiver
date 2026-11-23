"""Unit tests for PaperLedger state machine and full mock lifecycle replay."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import tempfile
import unittest

from alphaalgo_receiver import (
    WebhookReceiver,
    dispatch_handlers,
    generate_signing_secret,
    jsonl_file_handler,
    sign_event,
)
from examples.paper_ledger import (
    PaperLedger,
    load_from_jsonl,
    load_from_sqlite,
)
from scripts.send_mock_event import (
    SCENARIO_NAMES,
    SINGLE_EVENT_KINDS,
    build_mock_event,
    build_scenario,
)


class TestMockReplayAndPaperLedger(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = generate_signing_secret()
        self.now = 1_795_000_000.0

    def test_all_single_mock_kinds_and_invalid_rejected(self) -> None:
        for kind in SINGLE_EVENT_KINDS:
            ev = build_mock_event(kind, self.now, tag="unit")
            self.assertEqual(ev["schema_version"], 3)
            self.assertTrue(ev["event_id"].startswith("aa3-"))
            inst = ev["instrument"]
            if inst["kind"] == "single_option":
                self.assertEqual(
                    ev["option_symbol"], inst["legs"][0]["option_symbol"]
                )
            else:
                self.assertIsNone(ev["option_symbol"])

        with self.assertRaises(ValueError):
            build_mock_event("nonexistent_kind", self.now)
        with self.assertRaises(ValueError):
            build_scenario("nonexistent_scenario", self.now)

    def test_full_demo_end_to_end_with_receiver_sqlite_and_jsonl(
        self,
    ) -> None:
        steps = build_scenario("full_demo", self.now, tag="demo1")
        self.assertGreaterEqual(len(steps), 14)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "receipts.db"
            jsonl_path = Path(tmpdir) / "events.jsonl"
            csv_path = Path(tmpdir) / "ledger.csv"

            live_ledger = PaperLedger(clock=lambda: self.now)
            rec = WebhookReceiver(
                db_path,
                {"v1": self.secret},
                on_event=dispatch_handlers(
                    [
                        jsonl_file_handler(jsonl_path),
                        lambda ev: live_ledger.apply_event(
                            ev, received_at=self.now
                        ),
                    ]
                ),
                clock=lambda: self.now,
            )
            try:
                for step in steps:
                    raw = json.dumps(
                        step.event, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                    hdrs = sign_event(
                        step.event["event_id"],
                        int(self.now),
                        raw,
                        self.secret,
                        key_id="v1",
                    )
                    wire = raw + b" " if step.tamper_body else raw
                    status, body = rec.receive(wire, hdrs)
                    self.assertEqual(
                        status,
                        step.expected_status,
                        msg=f"step failed: {step.label} -> {body}",
                    )
            finally:
                rec.close()

            by_ref = {p.trade_ref: p for p in live_ledger.positions()}
            # 1-leg equity lifecycle reached CLOSED at rev 4.
            eq = by_ref["DEMO-EQ-demo1"]
            self.assertEqual(eq.status, "CLOSED")
            self.assertEqual(eq.last_revision, 4)
            self.assertEqual(eq.entry_quantity, 6)
            self.assertEqual(eq.remaining_quantity, 0)
            self.assertAlmostEqual(eq.cumulative_return_pct or 0.0, 44.32)
            self.assertEqual(eq.events_applied, 4)

            # 2-leg SPX vertical credit spread reached CLOSED at rev 2.
            spx = by_ref["DEMO-SPX-demo1"]
            self.assertEqual(spx.status, "CLOSED")
            self.assertEqual(spx.leg_count, 2)
            self.assertEqual(spx.instrument_kind, "vertical_credit_spread")

            # 4-leg SPX IBF closed via settlement_observation.
            ibf = by_ref["DEMO-IBF-demo1"]
            self.assertEqual(ibf.status, "CLOSED")
            self.assertEqual(ibf.leg_count, 4)
            self.assertEqual(ibf.record_kind, "settlement_observation")

            # Out-of-order trade kept rev 3 and ignored late rev 2.
            ooo = by_ref["DEMO-EQ-demo1-ooo"]
            self.assertEqual(ooo.last_revision, 3)
            self.assertEqual(ooo.last_event_kind, "partial_exit")
            self.assertEqual(ooo.status, "OPEN")

            # Stale entry and incomplete spread flagged properly.
            stale = by_ref["DEMO-STALE-demo1"]
            self.assertTrue(stale.expired_at_receipt)

            inc = by_ref["DEMO-INC-demo1"]
            self.assertFalse(inc.instrument_complete)

            stats = live_ledger.summary()
            self.assertEqual(stats["stale_revisions_ignored"], 1)
            self.assertEqual(stats["non_fill_events"], 1)
            self.assertEqual(stats["incomplete_instrument_events"], 1)
            self.assertEqual(stats["expired_entry_events"], 1)

            # Offline rebuild from SQLite and JSONL must match live state.
            db_ledger = load_from_sqlite(db_path)
            jsonl_ledger = load_from_jsonl(jsonl_path)
            self.assertEqual(
                [p.trade_ref for p in db_ledger.positions()],
                [p.trade_ref for p in live_ledger.positions()],
            )
            self.assertEqual(
                [p.trade_ref for p in jsonl_ledger.positions()],
                [p.trade_ref for p in live_ledger.positions()],
            )
            self.assertEqual(
                db_ledger.summary()["stale_revisions_ignored"], 1
            )

            # ASCII table and CSV export work cleanly.
            table = live_ledger.render_table()
            self.assertIn("DEMO-EQ-demo1", table)
            self.assertIn("INCOMPLETE", table)
            self.assertIn("EXPIRED", table)
            self.assertIn("settlement_observation", table)

            live_ledger.export_csv(csv_path)
            with csv_path.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), len(live_ledger.positions()))

    def test_invalid_events_and_scenario_registry(self) -> None:
        ledger = PaperLedger(clock=lambda: self.now)
        res1 = ledger.apply_event({"trade_revision": 1})
        self.assertEqual(res1.action, "ignored_invalid")
        res2 = ledger.apply_event({"trade_ref": "T1", "trade_revision": True})
        self.assertEqual(res2.action, "ignored_invalid")
        res3 = ledger.apply_event({"trade_ref": "T1", "trade_revision": -1})
        self.assertEqual(res3.action, "ignored_invalid")
        self.assertEqual(ledger.positions(), [])
        self.assertIn("(no trades tracked yet)", ledger.render_table())

        for name in SCENARIO_NAMES:
            self.assertTrue(len(build_scenario(name, self.now)) >= 2)


if __name__ == "__main__":
    unittest.main()
