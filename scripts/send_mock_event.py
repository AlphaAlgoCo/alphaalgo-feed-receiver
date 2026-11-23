#!/usr/bin/env python3
"""Send locally signed mock AlphaAlgo v3 events or full lifecycle scenarios.

Examples:
  # Single event (1-leg, 2-leg spread, 4-leg IBF, or edge case):
  python3 scripts/send_mock_event.py --kind equity_entry
  python3 scripts/send_mock_event.py --kind spx_spread_entry
  python3 scripts/send_mock_event.py --kind spx_ibf_entry

  # Full multi-step scenario replay (ideal alongside examples/paper_ledger.py):
  python3 scripts/send_mock_event.py --scenario full_demo
  python3 scripts/send_mock_event.py --scenario equity_lifecycle --delay 0.5
  python3 scripts/send_mock_event.py --scenario edge_cases --delay 0
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from alphaalgo_receiver.security import sign_event  # noqa: E402

SINGLE_EVENT_KINDS = (
    "equity_entry",
    "equity_entry_update",
    "equity_partial_exit",
    "equity_exit",
    "spx_spread_entry",
    "spx_spread_exit",
    "spx_ibf_entry",
    "spx_ibf_exit",
    "spx_ibf_settlement",
    "stale_entry",
    "incomplete_spread",
)

SCENARIO_NAMES = (
    "equity_lifecycle",
    "spread_lifecycle",
    "ibf_lifecycle",
    "edge_cases",
    "full_demo",
)


@dataclass(frozen=True)
class ReplayStep:
    """One HTTP POST step in a synthetic replay scenario."""

    label: str
    event: dict[str, Any]
    expected_status: int = 200
    tamper_body: bool = False


def _mock_event_id(source_event_id: str) -> str:
    raw = f"mock\0{source_event_id}".encode("utf-8")
    return "aa3-" + hashlib.sha256(raw).hexdigest()


def _leg(
    role: str,
    symbol: str,
    root: str,
    expiration: str,
    right: str,
    strike: float,
    entry_side: str,
    exit_side: str,
) -> dict[str, Any]:
    return {
        "role": role,
        "option_symbol": symbol,
        "root": root,
        "expiration": expiration,
        "right": right,
        "strike": strike,
        "ratio": 1,
        "entry_side": entry_side,
        "exit_side": exit_side,
    }


def _equity_instrument(
    occ: str = "NVDA261218C00150000",
    root: str = "NVDA",
    expiration: str = "2026-12-18",
    right: str = "C",
    strike: float = 150.0,
) -> dict[str, Any]:
    return {
        "descriptor_version": 1,
        "kind": "single_option",
        "complete": True,
        "incomplete_reason": None,
        "quantity_unit": "contracts",
        "contract_multiplier": 100,
        "legs": [
            _leg(
                "single",
                occ,
                root,
                expiration,
                right,
                strike,
                "buy_to_open",
                "sell_to_close",
            ),
        ],
    }


def _spx_spread_instrument(
    exp: str = "2026-11-23", *, complete: bool = True
) -> dict[str, Any]:
    short_leg = _leg(
        "short",
        "SPXW261123P06000000",
        "SPXW",
        exp,
        "P",
        6000.0,
        "sell_to_open",
        "buy_to_close",
    )
    long_leg = _leg(
        "long",
        "SPXW261123P05980000",
        "SPXW",
        exp,
        "P",
        5980.0,
        "buy_to_open",
        "sell_to_close",
    )
    if not complete:
        short_partial = {
            k: short_leg[k]
            for k in (
                "role",
                "option_symbol",
                "root",
                "expiration",
                "right",
                "strike",
            )
        }
        return {
            "descriptor_version": 1,
            "kind": "vertical_credit_spread",
            "structure": "CPS",
            "complete": False,
            "incomplete_reason": "missing_or_invalid_spread_leg",
            "quantity_unit": "spreads",
            "spread_width_points": None,
            "contract_multiplier": None,
            "entry_price_basis": "positive_net_credit_per_share",
            "exit_price_basis": "positive_net_debit_per_share",
            "return_basis": "original_entry_net_credit",
            "legs": [short_partial],
        }
    return {
        "descriptor_version": 1,
        "kind": "vertical_credit_spread",
        "structure": "CPS",
        "complete": True,
        "incomplete_reason": None,
        "quantity_unit": "spreads",
        "spread_width_points": 20.0,
        "contract_multiplier": 100,
        "entry_price_basis": "positive_net_credit_per_share",
        "exit_price_basis": "positive_net_debit_per_share",
        "return_basis": "original_entry_net_credit",
        "legs": [short_leg, long_leg],
    }


def _spx_ibf_instrument(exp: str = "2026-11-23") -> dict[str, Any]:
    return {
        "descriptor_version": 1,
        "kind": "iron_butterfly",
        "structure": "IBF",
        "complete": True,
        "incomplete_reason": None,
        "quantity_unit": "spreads",
        "center_strike": 6000.0,
        "spread_width_points": 15.0,
        "contract_multiplier": 100,
        "entry_price_basis": "positive_net_credit_per_share",
        "exit_price_basis": "positive_net_debit_per_share",
        "return_basis": "original_entry_net_credit",
        "legs": [
            _leg(
                "short_call",
                "SPXW261123C06000000",
                "SPXW",
                exp,
                "C",
                6000.0,
                "sell_to_open",
                "buy_to_close",
            ),
            _leg(
                "long_call",
                "SPXW261123C06015000",
                "SPXW",
                exp,
                "C",
                6015.0,
                "buy_to_open",
                "sell_to_close",
            ),
            _leg(
                "short_put",
                "SPXW261123P06000000",
                "SPXW",
                exp,
                "P",
                6000.0,
                "sell_to_open",
                "buy_to_close",
            ),
            _leg(
                "long_put",
                "SPXW261123P05985000",
                "SPXW",
                exp,
                "P",
                5985.0,
                "buy_to_open",
                "sell_to_close",
            ),
        ],
    }


def _base_envelope(
    source_id: str,
    trade_ref: str,
    strategy_id: str,
    sub_strategy: str | None,
    ticker: str,
    option_symbol: str | None,
    scale_x: float,
    qty: int,
    entry_price: float,
    now: float,
    instrument: dict[str, Any],
    *,
    event_kind: str = "entry",
    trade_revision: int = 1,
    record_kind: str = "fill",
    exit_fill_quantity: int = 0,
    cumulative_exit_quantity: int = 0,
    exit_fill_price: float | None = None,
    cumulative_pnl_dollars: float = 0.0,
    cumulative_return_pct: float = 0.0,
    observed_offset_sec: float = 0.0,
    expires_offset_sec: float | None = 30.0,
    expiry_reason: str | None = None,
    settlement_model: str | None = None,
    settlement_underlying_price: float | None = None,
) -> dict[str, Any]:
    remaining = qty - cumulative_exit_quantity
    is_entry = event_kind in ("entry", "entry_update")
    is_fill = record_kind == "fill"
    observed = now + observed_offset_sec
    expires_at = (
        observed + expires_offset_sec
        if is_entry and expires_offset_sec is not None
        else None
    )
    if is_fill:
        fill_ts: float | None = observed
        provenance = "broker_reported"
        broker_exec: bool | None = None
    else:
        fill_ts = None
        provenance = (
            "settlement_model_observation"
            if record_kind == "settlement_observation"
            else "non_execution_close_observation"
        )
        broker_exec = False

    return {
        "schema_version": 3,
        "event_id": _mock_event_id(source_id),
        "source_event_id": source_id,
        "source_id": "mock",
        "source_execution": {
            "live_origin_verified": is_fill,
            "broker": "tradier" if is_fill else None,
            "environment": "live" if is_fill else "unknown",
            "evidence_source": "broker_order_query" if is_fill else None,
        },
        "trade_ref": trade_ref,
        "trade_revision": trade_revision,
        "event_kind": event_kind,
        "record_kind": record_kind,
        "broker_execution": broker_exec,
        "settlement_model": settlement_model,
        "settlement_underlying_price": settlement_underlying_price,
        "strategy_id": strategy_id,
        "sub_strategy": sub_strategy,
        "ticker": ticker,
        "option_symbol": option_symbol,
        "reference_allocation_x": scale_x,
        "reference_stop_loss_fraction": None,
        "position_scale_x": scale_x,
        "position_scale_max_x": 1.5,
        "position_scale_basis": "system_base_unit_customer_defined",
        "position_scale_max_scope": "strategy_entry",
        "reference_stop_scenario_loss_pct": None,
        "normalized_price_stop_scenario_x": None,
        "allocation_basis": "system_base_unit_customer_defined",
        "entry_quantity": qty,
        "exit_fill_quantity": exit_fill_quantity,
        "cumulative_exit_quantity": cumulative_exit_quantity,
        "remaining_quantity": remaining,
        "entry_price": entry_price,
        "entry_cost": round(entry_price * qty * 100.0, 2),
        "exit_fill_price": exit_fill_price,
        "cumulative_pnl_dollars": cumulative_pnl_dollars,
        "cumulative_return_pct": cumulative_return_pct,
        "fill_timestamp": fill_ts,
        "observed_timestamp": observed,
        "fill_time_verified": is_fill,
        "broker_fill_time_unknown": not is_fill,
        "fill_time_provenance": provenance,
        "fill_time_unknown": False,
        "published_at": now,
        "expires_at": expires_at,
        "expiry_reason": expiry_reason,
        "requires_position_reconciliation": event_kind
        in ("entry_update", "partial_exit", "exit"),
        "instrument": instrument,
        "disclaimer": "Synthetic mock event for local receiver testing.",
    }


def build_mock_event(
    kind: str,
    now: float,
    *,
    tag: str | None = None,
) -> dict[str, Any]:
    """Build a schema v3 synthetic event matching production wire format."""
    suffix = tag or str(int(now))
    occ = "NVDA261218C00150000"

    if kind == "equity_entry":
        return _base_envelope(
            source_id=f"mock-eq-entry-{suffix}",
            trade_ref=f"DEMO-EQ-{suffix}",
            strategy_id="S608",
            sub_strategy=None,
            ticker="NVDA",
            option_symbol=occ,
            scale_x=0.75,
            qty=4,
            entry_price=4.25,
            now=now,
            instrument=_equity_instrument(occ),
            event_kind="entry",
            trade_revision=1,
        )

    if kind == "equity_entry_update":
        return _base_envelope(
            source_id=f"mock-eq-upd-{suffix}",
            trade_ref=f"DEMO-EQ-{suffix}",
            strategy_id="S608",
            sub_strategy=None,
            ticker="NVDA",
            option_symbol=occ,
            scale_x=1.0,
            qty=6,
            entry_price=4.40,
            now=now,
            instrument=_equity_instrument(occ),
            event_kind="entry_update",
            trade_revision=2,
        )

    if kind == "equity_partial_exit":
        return _base_envelope(
            source_id=f"mock-eq-pexit-{suffix}",
            trade_ref=f"DEMO-EQ-{suffix}",
            strategy_id="S608",
            sub_strategy=None,
            ticker="NVDA",
            option_symbol=occ,
            scale_x=1.0,
            qty=6,
            entry_price=4.40,
            now=now,
            instrument=_equity_instrument(occ),
            event_kind="partial_exit",
            trade_revision=3,
            exit_fill_quantity=3,
            cumulative_exit_quantity=3,
            exit_fill_price=6.10,
            cumulative_pnl_dollars=510.0,
            cumulative_return_pct=19.32,
        )

    if kind == "equity_exit":
        return _base_envelope(
            source_id=f"mock-eq-exit-{suffix}",
            trade_ref=f"DEMO-EQ-{suffix}",
            strategy_id="S608",
            sub_strategy=None,
            ticker="NVDA",
            option_symbol=occ,
            scale_x=1.0,
            qty=6,
            entry_price=4.40,
            now=now,
            instrument=_equity_instrument(occ),
            event_kind="exit",
            trade_revision=4,
            exit_fill_quantity=3,
            cumulative_exit_quantity=6,
            exit_fill_price=6.60,
            cumulative_pnl_dollars=1170.0,
            cumulative_return_pct=44.32,
        )

    if kind == "spx_spread_entry":
        return _base_envelope(
            source_id=f"mock-spx-entry-{suffix}",
            trade_ref=f"DEMO-SPX-{suffix}",
            strategy_id="S623",
            sub_strategy="CPS",
            ticker="SPX",
            option_symbol=None,
            scale_x=1.0,
            qty=1,
            entry_price=2.40,
            now=now,
            instrument=_spx_spread_instrument(),
            event_kind="entry",
            trade_revision=1,
        )

    if kind == "spx_spread_exit":
        return _base_envelope(
            source_id=f"mock-spx-exit-{suffix}",
            trade_ref=f"DEMO-SPX-{suffix}",
            strategy_id="S623",
            sub_strategy="CPS",
            ticker="SPX",
            option_symbol=None,
            scale_x=1.0,
            qty=1,
            entry_price=2.40,
            now=now,
            instrument=_spx_spread_instrument(),
            event_kind="exit",
            trade_revision=2,
            exit_fill_quantity=1,
            cumulative_exit_quantity=1,
            exit_fill_price=0.60,
            cumulative_pnl_dollars=180.0,
            cumulative_return_pct=75.0,
        )

    if kind == "spx_ibf_entry":
        return _base_envelope(
            source_id=f"mock-ibf-entry-{suffix}",
            trade_ref=f"DEMO-IBF-{suffix}",
            strategy_id="S662",
            sub_strategy="IBF",
            ticker="SPX",
            option_symbol=None,
            scale_x=1.0,
            qty=1,
            entry_price=11.20,
            now=now,
            instrument=_spx_ibf_instrument(),
            event_kind="entry",
            trade_revision=1,
        )

    if kind == "spx_ibf_exit":
        return _base_envelope(
            source_id=f"mock-ibf-exit-{suffix}",
            trade_ref=f"DEMO-IBF-{suffix}",
            strategy_id="S662",
            sub_strategy="IBF",
            ticker="SPX",
            option_symbol=None,
            scale_x=1.0,
            qty=1,
            entry_price=11.20,
            now=now,
            instrument=_spx_ibf_instrument(),
            event_kind="exit",
            trade_revision=2,
            exit_fill_quantity=1,
            cumulative_exit_quantity=1,
            exit_fill_price=6.40,
            cumulative_pnl_dollars=480.0,
            cumulative_return_pct=42.86,
        )

    if kind == "spx_ibf_settlement":
        return _base_envelope(
            source_id=f"mock-ibf-settle-{suffix}",
            trade_ref=f"DEMO-IBF-{suffix}",
            strategy_id="S662",
            sub_strategy="IBF",
            ticker="SPX",
            option_symbol=None,
            scale_x=1.0,
            qty=1,
            entry_price=11.20,
            now=now,
            instrument=_spx_ibf_instrument(),
            event_kind="exit",
            trade_revision=2,
            record_kind="settlement_observation",
            exit_fill_quantity=1,
            cumulative_exit_quantity=1,
            exit_fill_price=4.00,
            cumulative_pnl_dollars=720.0,
            cumulative_return_pct=64.29,
            settlement_model="spxw_european_cash_settlement_1600",
            settlement_underlying_price=6004.0,
        )

    if kind == "stale_entry":
        return _base_envelope(
            source_id=f"mock-stale-{suffix}",
            trade_ref=f"DEMO-STALE-{suffix}",
            strategy_id="S650",
            sub_strategy=None,
            ticker="SPY",
            option_symbol="SPY261124C00600000",
            scale_x=1.0,
            qty=2,
            entry_price=2.15,
            now=now,
            instrument=_equity_instrument(
                occ="SPY261124C00600000",
                root="SPY",
                expiration="2026-11-24",
                right="C",
                strike=600.0,
            ),
            event_kind="entry",
            trade_revision=1,
            observed_offset_sec=-90.0,
            expires_offset_sec=30.0,
            expiry_reason="stale_entry",
        )

    if kind == "incomplete_spread":
        return _base_envelope(
            source_id=f"mock-inc-{suffix}",
            trade_ref=f"DEMO-INC-{suffix}",
            strategy_id="S623",
            sub_strategy="CPS",
            ticker="SPX",
            option_symbol=None,
            scale_x=1.0,
            qty=1,
            entry_price=2.40,
            now=now,
            instrument=_spx_spread_instrument(complete=False),
            event_kind="entry",
            trade_revision=1,
        )

    raise ValueError(f"unsupported mock event kind: {kind}")


def build_scenario(
    name: str,
    now: float,
    *,
    tag: str | None = None,
) -> list[ReplayStep]:
    """Build a multi-step replay scenario exercising realistic feed flows."""
    run_tag = tag or str(int(now))

    if name == "equity_lifecycle":
        return [
            ReplayStep(
                "1-leg S608 entry (rev 1, qty 4)",
                build_mock_event("equity_entry", now, tag=run_tag),
            ),
            ReplayStep(
                "1-leg S608 entry_update (rev 2, scale up qty 6)",
                build_mock_event("equity_entry_update", now, tag=run_tag),
            ),
            ReplayStep(
                "1-leg S608 partial_exit (rev 3, sell 3 / 3 left)",
                build_mock_event("equity_partial_exit", now, tag=run_tag),
            ),
            ReplayStep(
                "1-leg S608 final exit (rev 4, closed +44.3%)",
                build_mock_event("equity_exit", now, tag=run_tag),
            ),
        ]

    if name == "spread_lifecycle":
        return [
            ReplayStep(
                "2-leg S623 SPX CPS entry (rev 1)",
                build_mock_event("spx_spread_entry", now, tag=run_tag),
            ),
            ReplayStep(
                "2-leg S623 SPX CPS exit (rev 2, closed +75.0%)",
                build_mock_event("spx_spread_exit", now, tag=run_tag),
            ),
        ]

    if name == "ibf_lifecycle":
        return [
            ReplayStep(
                "4-leg S662 SPX IBF entry (rev 1)",
                build_mock_event("spx_ibf_entry", now, tag=run_tag),
            ),
            ReplayStep(
                "4-leg S662 settlement_observation exit (rev 2)",
                build_mock_event("spx_ibf_settlement", now, tag=run_tag),
            ),
        ]

    if name == "edge_cases":
        dup_ev = build_mock_event(
            "spx_spread_entry", now, tag=f"{run_tag}-dup"
        )
        # Same event_id with altered payload triggers 409 Conflict.
        collision_ev = dict(dup_ev, entry_price=9.99)
        ooo_tag = f"{run_tag}-ooo"
        ooo_rev3 = build_mock_event("equity_partial_exit", now, tag=ooo_tag)
        ooo_rev2 = build_mock_event("equity_entry_update", now, tag=ooo_tag)
        tamper_ev = build_mock_event(
            "equity_entry", now, tag=f"{run_tag}-tamper"
        )
        return [
            ReplayStep("Baseline spread entry (first delivery)", dup_ev, 200),
            ReplayStep("Exact retry (expect 200 duplicate=true)", dup_ev, 200),
            ReplayStep(
                "Same event_id with mutated body (expect 409 Conflict)",
                collision_ev,
                409,
            ),
            ReplayStep(
                "Out-of-order: rev 3 arrives first", ooo_rev3, 200
            ),
            ReplayStep(
                "Out-of-order: older rev 2 arrives late (ledger ignores)",
                ooo_rev2,
                200,
            ),
            ReplayStep(
                "Stale entry past expires_at (expiry_reason=stale_entry)",
                build_mock_event("stale_entry", now, tag=run_tag),
                200,
            ),
            ReplayStep(
                "Incomplete multi-leg instrument (complete=false)",
                build_mock_event("incomplete_spread", now, tag=run_tag),
                200,
            ),
            ReplayStep(
                "Tampered HTTP body after signing (expect 401)",
                tamper_ev,
                401,
                tamper_body=True,
            ),
        ]

    if name == "full_demo":
        steps: list[ReplayStep] = []
        for sub in (
            "equity_lifecycle",
            "spread_lifecycle",
            "ibf_lifecycle",
            "edge_cases",
        ):
            steps.extend(build_scenario(sub, now, tag=run_tag))
        return steps

    raise ValueError(f"unsupported scenario: {name}")


def send_step(
    url: str,
    step: ReplayStep,
    secret: str,
    *,
    key_id: str = "v1",
    now: int | None = None,
    timeout: float = 10.0,
) -> tuple[int, str]:
    """Sign and POST a single ReplayStep, returning (http_status, body_text)."""
    ts = int(time.time()) if now is None else now
    body = json.dumps(
        step.event, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    headers = sign_event(
        step.event["event_id"], ts, body, secret, key_id=key_id
    )
    headers["Content-Type"] = "application/json"
    wire_body = (
        body + b" " if step.tamper_body else body
    )  # Mutate bytes after signing.

    req = urllib.request.Request(
        url, data=wire_body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), resp.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        return int(err.code), err.read().decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default=os.environ.get(
            "ALPHAALGO_RECEIVER_URL", "http://127.0.0.1:9091/events"
        ),
        help="Target receiver URL (default: http://127.0.0.1:9091/events)",
    )
    parser.add_argument(
        "--key-id",
        default="v1",
        help="Signing key ID (default: v1)",
    )
    parser.add_argument(
        "--kind",
        choices=SINGLE_EVENT_KINDS,
        default="equity_entry",
        help="Send one synthetic event (ignored when --scenario is set)",
    )
    parser.add_argument(
        "--scenario",
        choices=SCENARIO_NAMES,
        default="",
        help="Run a multi-step lifecycle or edge-case replay scenario",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.25,
        help="Seconds to pause between scenario steps (default: 0.25)",
    )
    parser.add_argument(
        "--tag",
        default="",
        help="Optional deterministic suffix for trade_ref / source_event_id",
    )
    args = parser.parse_args()

    keys = json.loads(os.environ.get("ALPHAALGO_RECEIVER_KEYS_JSON", "{}"))
    if args.key_id not in keys:
        parser.error(
            f"Key ID {args.key_id!r} not found in ALPHAALGO_RECEIVER_KEYS_JSON"
        )

    now = int(time.time())
    tag = args.tag or str(now)
    if args.scenario:
        steps = build_scenario(args.scenario, float(now), tag=tag)
    else:
        steps = [
            ReplayStep(
                args.kind,
                build_mock_event(args.kind, float(now), tag=tag),
                200,
            )
        ]

    failures = 0
    for idx, step in enumerate(steps, start=1):
        status, text = send_step(
            args.url,
            step,
            keys[args.key_id],
            key_id=args.key_id,
            now=int(time.time()),
        )
        ok = status == step.expected_status
        marker = "OK" if ok else "FAIL"
        if args.scenario:
            print(
                f"[{idx}/{len(steps)}] {marker} | {step.label}\n"
                f"    HTTP {status} (expected {step.expected_status}): {text}"
            )
        else:
            stream = sys.stdout if ok else sys.stderr
            print(f"HTTP {status}: {text}", file=stream)
        if not ok:
            failures += 1
        if args.scenario and idx < len(steps) and args.delay > 0:
            time.sleep(args.delay)

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
