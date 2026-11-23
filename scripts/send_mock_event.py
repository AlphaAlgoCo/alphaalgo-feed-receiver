#!/usr/bin/env python3
"""Send a locally signed mock AlphaAlgo v3 event to test your receiver."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from alphaalgo_receiver.security import sign_event  # noqa: E402


def _mock_event_id(source_event_id: str) -> str:
    raw = f"mock\0{source_event_id}".encode("utf-8")
    return "aa3-" + hashlib.sha256(raw).hexdigest()


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
    instrument: dict,
) -> dict:
    return {
        "schema_version": 3,
        "event_id": _mock_event_id(source_id),
        "source_event_id": source_id,
        "source_id": "mock",
        "trade_ref": trade_ref,
        "trade_revision": 1,
        "event_kind": "entry",
        "record_kind": "fill",
        "strategy_id": strategy_id,
        "sub_strategy": sub_strategy,
        "ticker": ticker,
        "option_symbol": option_symbol,
        "position_scale_x": scale_x,
        "allocation_basis": "system_base_unit_customer_defined",
        "entry_quantity": qty,
        "exit_fill_quantity": 0,
        "cumulative_exit_quantity": 0,
        "remaining_quantity": qty,
        "entry_price": entry_price,
        "exit_fill_price": None,
        "cumulative_pnl_dollars": 0.0,
        "cumulative_return_pct": 0.0,
        "fill_timestamp": now,
        "observed_timestamp": now,
        "fill_time_verified": True,
        "broker_fill_time_unknown": False,
        "fill_time_provenance": "broker_reported",
        "fill_time_unknown": False,
        "published_at": now,
        "expires_at": now + 30.0,
        "expiry_reason": None,
        "requires_position_reconciliation": False,
        "instrument": instrument,
        "disclaimer": "Synthetic mock event for local receiver testing.",
    }


def _leg(
    role: str,
    symbol: str,
    root: str,
    expiration: str,
    right: str,
    strike: float,
    entry_side: str,
    exit_side: str,
) -> dict:
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


def build_mock_event(kind: str, now: float) -> dict:
    """Build a schema v3 synthetic event matching production wire format."""
    if kind == "spx_ibf_entry":
        exp = "2026-11-23"
        instrument = {
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
        return _base_envelope(
            source_id=f"mock-ibf-{int(now)}",
            trade_ref="DEMO-IBF-001",
            strategy_id="S662",
            sub_strategy="IBF",
            ticker="SPX",
            option_symbol=None,
            scale_x=1.0,
            qty=1,
            entry_price=11.20,
            now=now,
            instrument=instrument,
        )

    if kind == "spx_spread_entry":
        exp = "2026-11-23"
        instrument = {
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
            "legs": [
                _leg(
                    "short",
                    "SPXW261123P06000000",
                    "SPXW",
                    exp,
                    "P",
                    6000.0,
                    "sell_to_open",
                    "buy_to_close",
                ),
                _leg(
                    "long",
                    "SPXW261123P05980000",
                    "SPXW",
                    exp,
                    "P",
                    5980.0,
                    "buy_to_open",
                    "sell_to_close",
                ),
            ],
        }
        return _base_envelope(
            source_id=f"mock-spx-{int(now)}",
            trade_ref="DEMO-SPX-001",
            strategy_id="S623",
            sub_strategy="CPS",
            ticker="SPX",
            option_symbol=None,
            scale_x=1.0,
            qty=1,
            entry_price=2.40,
            now=now,
            instrument=instrument,
        )

    occ = "NVDA261218C00150000"
    instrument = {
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
                "NVDA",
                "2026-12-18",
                "C",
                150.0,
                "buy_to_open",
                "sell_to_close",
            ),
        ],
    }
    return _base_envelope(
        source_id=f"mock-eq-{int(now)}",
        trade_ref="DEMO-EQ-001",
        strategy_id="S608",
        sub_strategy=None,
        ticker="NVDA",
        option_symbol=occ,
        scale_x=0.75,
        qty=2,
        entry_price=4.25,
        now=now,
        instrument=instrument,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:9091/events",
        help="Target receiver URL",
    )
    parser.add_argument(
        "--key-id",
        default="v1",
        help="Signing key ID (default: v1)",
    )
    parser.add_argument(
        "--kind",
        choices=("equity_entry", "spx_spread_entry", "spx_ibf_entry"),
        default="equity_entry",
    )
    args = parser.parse_args()

    keys = json.loads(os.environ.get("ALPHAALGO_RECEIVER_KEYS_JSON", "{}"))
    if args.key_id not in keys:
        parser.error(
            f"Key ID {args.key_id!r} not found in ALPHAALGO_RECEIVER_KEYS_JSON"
        )

    now = int(time.time())
    event = build_mock_event(args.kind, float(now))
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    headers = sign_event(
        event["event_id"], now, body, keys[args.key_id], key_id=args.key_id
    )
    headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        args.url, data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"HTTP {resp.status}: {resp.read().decode('utf-8')}")
    except urllib.error.HTTPError as err:
        print(
            f"HTTP {err.code}: {err.read().decode('utf-8')}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
