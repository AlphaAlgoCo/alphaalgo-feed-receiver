#!/usr/bin/env python3
"""Read-only local position state tracker (Paper Ledger) for AlphaAlgo Feed v3.

Demonstrates how downstream consumers turn discrete webhook events
(``entry`` -> ``entry_update`` -> ``partial_exit`` -> ``exit``) into an
authoritative per-``trade_ref`` position table with:

  - Monotonic ``trade_revision`` ordering (out-of-order older revisions ignored)
  - Uniform handling of 1-leg, 2-leg vertical spreads, and 4-leg IBFs
  - Explicit tracking of non-fill records (``settlement_observation`` /
    ``non_execution_close``) and incomplete instruments (``complete=False``)
  - Receipt-time expiry and delivery-latency telemetry

Strictly read-only telemetry — never connects to a brokerage or places orders.

Usage:
  # 1. Run a live demo receiver that prints the updated ledger on every event:
  python3 examples/paper_ledger.py --serve --port 9091

  # 2. Rebuild the ledger from an existing receiver SQLite DB or JSONL log:
  python3 examples/paper_ledger.py --from-db ./receipts.db
  python3 examples/paper_ledger.py --from-jsonl ./events.jsonl \
    --export-csv ./ledger.csv
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass
import json
import logging
import math
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time
from typing import Any, Callable, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from alphaalgo_receiver import (  # noqa: E402
    WebhookReceiver,
    describe_contract,
    format_event_summary,
)
from alphaalgo_receiver.cli import serve_receiver  # noqa: E402
from alphaalgo_receiver.doctor import resolve_signing_keys  # noqa: E402


def _finite(value: Any) -> float | None:
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    ):
        return float(value)
    return None


def _non_neg_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


@dataclass
class TradePosition:
    """Latest aggregated state for a single ``trade_ref``."""

    trade_ref: str
    strategy_id: str
    sub_strategy: str | None
    ticker: str
    contract: str
    instrument_kind: str
    leg_count: int
    instrument_complete: bool
    status: str  # "OPEN" | "CLOSED"
    last_revision: int
    last_event_kind: str
    record_kind: str
    position_scale_x: float | None
    entry_quantity: int
    cumulative_exit_quantity: int
    remaining_quantity: int
    entry_price: float | None
    last_exit_price: float | None
    cumulative_pnl_dollars: float | None
    cumulative_return_pct: float | None
    requires_reconciliation: bool
    expired_at_receipt: bool
    delivery_latency_ms: float | None
    events_applied: int
    updated_at: float


@dataclass
class ApplyResult:
    """Outcome of applying a single v3 event to the Paper Ledger."""

    action: str  # "applied" | "ignored_stale_revision" | "ignored_invalid"
    trade_ref: str
    revision: int
    status: str | None
    note: str = ""


class PaperLedger:
    """Thread-safe, read-only position state machine keyed by ``trade_ref``."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._positions: dict[str, TradePosition] = {}
        self.applied_count = 0
        self.stale_revision_count = 0
        self.non_fill_count = 0
        self.incomplete_instrument_count = 0
        self.expired_entry_count = 0
        self._latencies_ms: list[float] = []

    def apply_event(
        self,
        event: Mapping[str, Any],
        *,
        received_at: float | None = None,
    ) -> ApplyResult:
        """Apply one verified v3 event, enforcing monotonic trade_revision."""
        trade_ref = str(event.get("trade_ref") or "").strip()
        revision = _non_neg_int(event.get("trade_revision"))
        if not trade_ref or revision is None:
            return ApplyResult(
                action="ignored_invalid",
                trade_ref=trade_ref or "-",
                revision=-1,
                status=None,
                note="missing trade_ref or non-negative integer trade_revision",
            )

        now = float(self._clock() if received_at is None else received_at)
        event_kind = str(event.get("event_kind") or "unknown")
        record_kind = str(event.get("record_kind") or "fill")
        inst = event.get("instrument")
        inst_map = inst if isinstance(inst, Mapping) else {}
        inst_kind = str(inst_map.get("kind") or "unknown")
        legs = inst_map.get("legs")
        leg_count = len(legs) if isinstance(legs, list) else 0
        complete = bool(inst_map.get("complete", False))

        observed_ts = _finite(event.get("observed_timestamp"))
        latency_ms: float | None = None
        if observed_ts is not None:
            latency_ms = max(0.0, (now - observed_ts) * 1000.0)

        expires_at = _finite(event.get("expires_at"))
        expired = bool(
            event_kind in ("entry", "entry_update")
            and expires_at is not None
            and now > expires_at
        )

        with self._lock:
            prior = self._positions.get(trade_ref)
            if prior is not None and revision <= prior.last_revision:
                self.stale_revision_count += 1
                return ApplyResult(
                    action="ignored_stale_revision",
                    trade_ref=trade_ref,
                    revision=revision,
                    status=prior.status,
                    note=(
                        f"rev {revision} <= applied rev {prior.last_revision}"
                    ),
                )

            entry_qty = _non_neg_int(event.get("entry_quantity"))
            cum_exit = _non_neg_int(event.get("cumulative_exit_quantity"))
            remaining = _non_neg_int(event.get("remaining_quantity"))

            if entry_qty is None:
                entry_qty = prior.entry_quantity if prior else 0
            if cum_exit is None:
                cum_exit = prior.cumulative_exit_quantity if prior else 0
            if remaining is None:
                remaining = max(0, entry_qty - cum_exit)

            is_closed = event_kind == "exit" or (
                entry_qty > 0 and remaining == 0
            )
            status = "CLOSED" if is_closed else "OPEN"

            entry_px = _finite(event.get("entry_price"))
            if entry_px is None and prior is not None:
                entry_px = prior.entry_price

            exit_px = _finite(event.get("exit_fill_price"))
            if exit_px is None and prior is not None:
                exit_px = prior.last_exit_price

            pnl_usd = _finite(event.get("cumulative_pnl_dollars"))
            if pnl_usd is None and prior is not None:
                pnl_usd = prior.cumulative_pnl_dollars

            ret_pct = _finite(event.get("cumulative_return_pct"))
            if ret_pct is None and prior is not None:
                ret_pct = prior.cumulative_return_pct

            scale_x = _finite(event.get("position_scale_x"))
            if scale_x is None and prior is not None:
                scale_x = prior.position_scale_x

            sub = event.get("sub_strategy")
            sub_str = str(sub) if isinstance(sub, str) and sub else None

            pos = TradePosition(
                trade_ref=trade_ref,
                strategy_id=str(event.get("strategy_id") or "UNKNOWN"),
                sub_strategy=sub_str,
                ticker=str(event.get("ticker") or "-"),
                contract=describe_contract(event),
                instrument_kind=inst_kind,
                leg_count=leg_count,
                instrument_complete=complete,
                status=status,
                last_revision=revision,
                last_event_kind=event_kind,
                record_kind=record_kind,
                position_scale_x=scale_x,
                entry_quantity=entry_qty,
                cumulative_exit_quantity=cum_exit,
                remaining_quantity=remaining,
                entry_price=entry_px,
                last_exit_price=exit_px,
                cumulative_pnl_dollars=pnl_usd,
                cumulative_return_pct=ret_pct,
                requires_reconciliation=bool(
                    event.get("requires_position_reconciliation", False)
                ),
                expired_at_receipt=expired,
                delivery_latency_ms=latency_ms,
                events_applied=(prior.events_applied + 1) if prior else 1,
                updated_at=now,
            )
            self._positions[trade_ref] = pos
            self.applied_count += 1
            if record_kind != "fill":
                self.non_fill_count += 1
            if not complete:
                self.incomplete_instrument_count += 1
            if expired:
                self.expired_entry_count += 1
            if latency_ms is not None:
                self._latencies_ms.append(latency_ms)

            notes: list[str] = []
            if record_kind != "fill":
                notes.append(f"record_kind={record_kind}")
            if not complete:
                reason = inst_map.get("incomplete_reason") or "unknown"
                notes.append(f"incomplete_instrument={reason}")
            if expired:
                notes.append("expired_at_receipt")
            return ApplyResult(
                action="applied",
                trade_ref=trade_ref,
                revision=revision,
                status=status,
                note=", ".join(notes),
            )

    def positions(self, *, status: str | None = None) -> list[TradePosition]:
        """Return positions sorted by trade_ref, optionally filtered."""
        with self._lock:
            items = list(self._positions.values())
        if status is not None:
            items = [p for p in items if p.status == status]
        return sorted(items, key=lambda p: (p.strategy_id, p.trade_ref))

    def summary(self) -> dict[str, Any]:
        """Return compact telemetry counters across all tracked trades."""
        with self._lock:
            all_pos = list(self._positions.values())
            latencies = list(self._latencies_ms)
            counters = {
                "applied_events": self.applied_count,
                "stale_revisions_ignored": self.stale_revision_count,
                "non_fill_events": self.non_fill_count,
                "incomplete_instrument_events": (
                    self.incomplete_instrument_count
                ),
                "expired_entry_events": self.expired_entry_count,
            }
        open_pos = [p for p in all_pos if p.status == "OPEN"]
        closed_pos = [p for p in all_pos if p.status == "CLOSED"]
        realized_pnl = sum(
            p.cumulative_pnl_dollars or 0.0 for p in closed_pos
        )
        avg_lat = (
            round(sum(latencies) / len(latencies), 1) if latencies else None
        )
        return {
            **counters,
            "total_trades": len(all_pos),
            "open_trades": len(open_pos),
            "closed_trades": len(closed_pos),
            "realized_pnl_dollars": round(realized_pnl, 2),
            "avg_delivery_latency_ms": avg_lat,
        }

    def render_table(self) -> str:
        """Render a human-readable ASCII summary of open & closed positions."""
        stats = self.summary()
        rows = self.positions()
        lines = [
            "=" * 94,
            (
                "AlphaAlgo Paper Ledger (Read-Only Telemetry) | "
                f"open={stats['open_trades']} closed={stats['closed_trades']} "
                f"applied={stats['applied_events']} "
                f"stale_ignored={stats['stale_revisions_ignored']} "
                f"non_fill={stats['non_fill_events']} "
                f"incomplete={stats['incomplete_instrument_events']}"
            ),
            "-" * 94,
            (
                f"{'STATUS':<7} {'STRAT':<6} {'TRADE_REF':<20} {'TICKER':<6} "
                f"{'CONTRACT':<22} {'QTY':<7} {'ENTRY':>7} {'EXIT':>7} "
                f"{'RET%':>8}  FLAGS"
            ),
            "-" * 94,
        ]
        if not rows:
            lines.append("(no trades tracked yet)")
        for pos in rows:
            qty_str = f"{pos.remaining_quantity}/{pos.entry_quantity}"
            entry_str = (
                f"{pos.entry_price:.2f}"
                if pos.entry_price is not None
                else "-"
            )
            exit_str = (
                f"{pos.last_exit_price:.2f}"
                if pos.last_exit_price is not None
                else "-"
            )
            ret_str = (
                f"{pos.cumulative_return_pct:+.1f}%"
                if pos.cumulative_return_pct is not None
                else "-"
            )
            flags: list[str] = []
            if pos.record_kind != "fill":
                flags.append(pos.record_kind)
            if not pos.instrument_complete:
                flags.append("INCOMPLETE")
            if pos.expired_at_receipt:
                flags.append("EXPIRED")
            if pos.requires_reconciliation:
                flags.append("RECONCILE")
            lines.append(
                f"{pos.status:<7} {pos.strategy_id:<6} "
                f"{pos.trade_ref[:20]:<20} {pos.ticker[:6]:<6} "
                f"{pos.contract[:22]:<22} {qty_str:<7} "
                f"{entry_str:>7} {exit_str:>7} {ret_str:>8}  "
                f"{','.join(flags) if flags else '-'}"
            )
        lines.append("=" * 94)
        return "\n".join(lines)

    def export_csv(self, path: str | Path) -> None:
        """Write current trade positions to a CSV file."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        rows = self.positions()
        fieldnames = list(TradePosition.__dataclass_fields__.keys())
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for pos in rows:
                writer.writerow(asdict(pos))


def load_from_sqlite(
    db_path: str | Path, ledger: PaperLedger | None = None
) -> PaperLedger:
    """Replay persisted receipts from a WebhookReceiver SQLite database."""
    target = ledger or PaperLedger()
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT received_at, body FROM receipts ORDER BY rowid ASC"
        ).fetchall()
    finally:
        conn.close()
    for received_at, body in rows:
        event = json.loads(
            body.decode("utf-8") if isinstance(body, bytes) else str(body)
        )
        target.apply_event(event, received_at=float(received_at))
    return target


def load_from_jsonl(
    jsonl_path: str | Path, ledger: PaperLedger | None = None
) -> PaperLedger:
    """Replay verified events from a JSONL log file."""
    target = ledger or PaperLedger()
    with Path(jsonl_path).open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            event = json.loads(stripped)
            target.apply_event(
                event, received_at=_finite(event.get("published_at"))
            )
    return target


def replay_events(
    events: Iterable[Mapping[str, Any]],
    ledger: PaperLedger | None = None,
) -> PaperLedger:
    """Apply an in-memory sequence of events into a PaperLedger."""
    target = ledger or PaperLedger()
    for ev in events:
        target.apply_event(ev)
    return target


def _serve_live_ledger(args: argparse.Namespace) -> None:
    try:
        keys = resolve_signing_keys(
            raw_secret=os.environ.get("ALPHAALGO_SIGNING_SECRET", ""),
            raw_keys_json=os.environ.get("ALPHAALGO_RECEIVER_KEYS_JSON", ""),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from None

    ledger = PaperLedger()
    if args.database != ":memory:" and Path(args.database).exists():
        load_from_sqlite(args.database, ledger)

    def _on_event(event: dict[str, Any]) -> None:
        res = ledger.apply_event(event)
        print(
            f"\n-> {format_event_summary(event)} "
            f"[{res.action}{': ' + res.note if res.note else ''}]"
        )
        print(ledger.render_table(), flush=True)

    app = WebhookReceiver(args.database, keys, on_event=_on_event)
    print(
        f"Paper Ledger Receiver listening on "
        f"http://{args.host}:{args.port}/events (db: {args.database})",
        flush=True,
    )
    print(ledger.render_table(), flush=True)
    try:
        serve_receiver(app, args.host, args.port)
    finally:
        if args.export_csv:
            ledger.export_csv(args.export_csv)
        app.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only local Paper Ledger for AlphaAlgo Feed v3 events."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--from-db",
        help="Rebuild ledger from an existing receiver SQLite database",
    )
    mode.add_argument(
        "--from-jsonl",
        help="Rebuild ledger from an existing JSONL event log",
    )
    mode.add_argument(
        "--serve",
        action="store_true",
        help="Run a live webhook receiver that prints ledger updates",
    )
    parser.add_argument(
        "--database",
        default=os.environ.get("ALPHAALGO_DB_PATH", "./paper_receipts.db"),
        help="SQLite receipts DB used with --serve",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("ALPHAALGO_HOST", "127.0.0.1"),
        help="Bind host used with --serve (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("ALPHAALGO_PORT", "9091")),
        help="Bind port used with --serve (default: 9091)",
    )
    parser.add_argument(
        "--export-csv",
        default="",
        help="Optional CSV path to write the aggregated trade table",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)
    if args.serve:
        _serve_live_ledger(args)
        return

    ledger = (
        load_from_sqlite(args.from_db)
        if args.from_db
        else load_from_jsonl(args.from_jsonl)
    )
    print(ledger.render_table())
    if args.export_csv:
        ledger.export_csv(args.export_csv)
        print(f"Exported CSV to {args.export_csv}")


if __name__ == "__main__":
    main()
