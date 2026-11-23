"""Event handlers — START HERE to customize what happens after an event arrives.

Every event passed to these functions has ALREADY been:
  1. Cryptographically verified (HMAC-SHA256 on exact raw HTTP bytes).
  2. Checked for timestamp freshness (within +/-300 seconds).
  3. Deduplicated and durably persisted in SQLite by `event_id`.

Keep handlers fast (or offload slow I/O to a background thread/queue) so the
HTTP server returns `200 OK` promptly.

This module is strictly read-only telemetry. It never places brokerage orders.
"""
from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
import threading
from typing import Any, Callable, Iterable, Mapping
import urllib.parse
import urllib.request

logger = logging.getLogger("alphaalgo_receiver.handlers")

EventHandler = Callable[[dict[str, Any]], None]

_DISCORD_HOSTS = frozenset(("discord.com", "discordapp.com"))


def _is_finite_number(value: Any) -> bool:
    """Return True for finite int/float values (explicitly excluding bool)."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def on_verified_event(event: dict[str, Any]) -> None:
    """Default extension hook invoked once per unique verified v3 event.

    Customize this function to integrate AlphaAlgo events into your own
    research pipeline, alerting channel, or analytics database.

    Key fields available on ``event``:
      - ``event["event_kind"]``: "entry", "entry_update", "partial_exit", "exit"
      - ``event["record_kind"]``: "fill" for broker-confirmed live fills
      - ``event["strategy_id"]``: canonical strategy ID (e.g. "S608", "S623")
      - ``event["trade_ref"]``: atomic trade ID linking entry -> exit
      - ``event["trade_revision"]``: monotonic revision integer
      - ``event["ticker"]``: underlying symbol (e.g. "SPX", "NVDA")
      - ``event["option_symbol"]``: OCC string for single_option; None for
        multi-leg instruments (always inspect ``event["instrument"]["legs"]``)
      - ``event["instrument"]``: ``kind`` in ("single_option",
        "vertical_credit_spread", "iron_butterfly"), ``complete``, and uniform
        ``legs[]`` with role/option_symbol/root/expiration/right/strike/ratio
      - ``event["fill_time_verified"]`` / ``event["expires_at"]``
      - ``event["requires_position_reconciliation"]``
      - ``event["position_scale_x"]``: relative system base-unit scale
      - ``event["entry_price"]`` / ``event["exit_fill_price"]``
      - ``event["cumulative_return_pct"]`` / ``event["cumulative_pnl_dollars"]``
    """
    # >>> ADD YOUR OWN READ-ONLY LOGIC HERE <<<
    # Example: filter by strategy_id, save to Postgres, or alert Telegram.
    logger.info("Event received: %s", format_event_summary(event))


def _describe_contract(event: Mapping[str, Any]) -> str:
    """Summarize the single OCC symbol or multi-leg instrument structure."""
    symbol = event.get("option_symbol")
    if isinstance(symbol, str) and symbol:
        return symbol
    inst = event.get("instrument")
    if isinstance(inst, Mapping):
        legs = inst.get("legs")
        leg_count = len(legs) if isinstance(legs, list) else 0
        label = str(inst.get("structure") or inst.get("kind") or "combo")
        if leg_count:
            return f"{label}({leg_count}-leg)"
        return label
    return "-"


def format_event_summary(event: Mapping[str, Any]) -> str:
    """Format a compact, single-line summary of a verified v3 event."""
    kind = str(event.get("event_kind", "unknown")).upper()
    strategy = str(event.get("strategy_id", "UNKNOWN"))
    trade_ref = str(event.get("trade_ref", "-"))
    ticker = str(event.get("ticker", "-"))
    contract = _describe_contract(event)

    scale = event.get("position_scale_x")
    scale_str = f"{scale:.2f}x" if _is_finite_number(scale) else "-"
    entry_px = event.get("entry_price")
    exit_px = event.get("exit_fill_price")
    pnl_pct = event.get("cumulative_return_pct")

    parts = [
        f"[{kind}]",
        strategy,
        f"#{trade_ref}",
        ticker,
        contract,
        f"scale={scale_str}",
    ]
    if _is_finite_number(entry_px):
        parts.append(f"entry={entry_px:.2f}")
    if _is_finite_number(exit_px):
        parts.append(f"exit={exit_px:.2f}")
    if _is_finite_number(pnl_pct):
        parts.append(f"ret={pnl_pct:+.2f}%")
    return " | ".join(parts)


def jsonl_file_handler(path: str | Path) -> EventHandler:
    """Return a thread-safe handler that appends verified events to a JSONL."""
    target = Path(path)
    lock = threading.Lock()

    def _write(event: dict[str, Any]) -> None:
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        with lock:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8") as handle:
                handle.write(line)
            os.chmod(target, 0o600)

    return _write


def _validate_discord_url(webhook_url: str) -> None:
    """Ensure Discord webhook URL is HTTPS on an official Discord host."""
    parsed = urllib.parse.urlparse(webhook_url)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or host not in _DISCORD_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/api/webhooks/")
    ):
        raise ValueError("invalid_discord_webhook_url")


def _build_discord_payload(event: Mapping[str, Any]) -> bytes:
    """Build a mention-safe Discord JSON payload from a verified event."""
    clean = (
        format_event_summary(event)
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")
    )
    body = {
        "content": f"`{clean}`",
        "allowed_mentions": {"parse": []},
    }
    return json.dumps(body).encode("utf-8")


def discord_webhook_handler(
    webhook_url: str,
    *,
    timeout: float = 5.0,
) -> EventHandler:
    """Return a read-only Discord webhook notifier using Python stdlib only."""
    _validate_discord_url(webhook_url)

    def _notify(event: dict[str, Any]) -> None:
        payload = _build_discord_payload(event)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "alphaalgo-feed-receiver/1.0",
        }
        req = urllib.request.Request(
            webhook_url, data=payload, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout):
                pass
        except Exception as exc:
            logger.warning(
                "Discord forward failed for %s: %s",
                event.get("event_id"),
                exc,
            )

    return _notify


def dispatch_handlers(handlers: Iterable[EventHandler]) -> EventHandler:
    """Compose multiple handlers so a failure in one does not block others."""
    registered = tuple(handlers)

    def _dispatch(event: dict[str, Any]) -> None:
        for handler in registered:
            try:
                handler(event)
            except Exception as exc:
                logger.exception(
                    "Handler %s failed for %s: %s",
                    getattr(handler, "__name__", repr(handler)),
                    event.get("event_id"),
                    exc,
                )

    return _dispatch
