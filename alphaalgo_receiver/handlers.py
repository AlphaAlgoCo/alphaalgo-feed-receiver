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
import queue
import re
import threading
from typing import Any, Callable, Iterable, Mapping
import urllib.parse
import urllib.request

logger = logging.getLogger("alphaalgo_receiver.handlers")

EventHandler = Callable[[dict[str, Any]], None]

_DISCORD_HOSTS = frozenset(("discord.com", "discordapp.com"))
_TELEGRAM_API_BASE = "https://api.telegram.org"
_TELEGRAM_TOKEN_RE = re.compile(r"\d+:[A-Za-z0-9_\-]{20,}\Z")
_TELEGRAM_CHAT_ID_RE = re.compile(r"(?:-?\d+|@[A-Za-z0-9_]{5,})\Z")
_USER_AGENT = "alphaalgo-feed-receiver/1.0"
_STOP_SENTINEL = object()


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


def describe_contract(event: Mapping[str, Any]) -> str:
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
    contract = describe_contract(event)

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


def _sanitize_summary(event: Mapping[str, Any]) -> str:
    """Return a single-line, backtick-safe summary for chat sinks."""
    return (
        format_event_summary(event)
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _post_json(
    url: str,
    payload: bytes,
    *,
    timeout: float,
    sink_name: str,
    event_id: Any,
    redact_error_url: bool = False,
) -> None:
    """POST JSON to an outbound read-only sink without propagating errors."""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": _USER_AGENT,
    }
    req = urllib.request.Request(
        url, data=payload, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            pass
    except Exception as exc:
        if redact_error_url:
            detail = f"{type(exc).__name__}(code={getattr(exc, 'code', None)})"
        else:
            detail = str(exc)
        logger.warning(
            "%s forward failed for %s: %s",
            sink_name,
            event_id,
            detail,
        )


def _build_discord_payload(event: Mapping[str, Any]) -> bytes:
    """Build a mention-safe Discord JSON payload from a verified event."""
    body = {
        "content": f"`{_sanitize_summary(event)}`",
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
        _post_json(
            webhook_url,
            _build_discord_payload(event),
            timeout=timeout,
            sink_name="Discord",
            event_id=event.get("event_id"),
            redact_error_url=True,
        )

    return _notify


def _validate_telegram_config(bot_token: str, chat_id: str | int) -> str:
    """Validate Telegram Bot API token and chat_id, returning str chat_id."""
    if not isinstance(bot_token, str) or not _TELEGRAM_TOKEN_RE.fullmatch(
        bot_token.strip()
    ):
        raise ValueError("invalid_telegram_bot_token")
    if isinstance(chat_id, bool):
        raise ValueError("invalid_telegram_chat_id")
    normalized_chat = str(chat_id).strip()
    if not _TELEGRAM_CHAT_ID_RE.fullmatch(normalized_chat):
        raise ValueError("invalid_telegram_chat_id")
    return normalized_chat


def _build_telegram_payload(
    event: Mapping[str, Any], chat_id: str
) -> bytes:
    """Build a plain-text Telegram sendMessage payload (no link previews)."""
    body = {
        "chat_id": chat_id,
        "text": _sanitize_summary(event),
        "disable_web_page_preview": True,
    }
    return json.dumps(body).encode("utf-8")


def telegram_bot_handler(
    bot_token: str,
    chat_id: str | int,
    *,
    timeout: float = 5.0,
) -> EventHandler:
    """Return a read-only Telegram Bot notifier using Python stdlib only."""
    normalized_chat = _validate_telegram_config(bot_token, chat_id)
    endpoint = f"{_TELEGRAM_API_BASE}/bot{bot_token.strip()}/sendMessage"

    def _notify(event: dict[str, Any]) -> None:
        _post_json(
            endpoint,
            _build_telegram_payload(event, normalized_chat),
            timeout=timeout,
            sink_name="Telegram",
            event_id=event.get("event_id"),
            redact_error_url=True,
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


class AsyncEventDispatcher:
    """Non-blocking background worker queue for slow downstream handlers.

    Keeps ``POST /events`` responses fast even if outbound webhooks (Discord,
    Telegram, databases) experience latency spikes. Events are processed in
    FIFO order on a single daemon thread; if the bounded queue fills up, new
    events are dropped with a warning rather than blocking HTTP ``200 OK``.
    """

    def __init__(
        self,
        handler: EventHandler,
        *,
        max_queue_size: int = 1000,
    ) -> None:
        if (
            not isinstance(max_queue_size, int)
            or isinstance(max_queue_size, bool)
            or max_queue_size <= 0
        ):
            raise ValueError("max_queue_size must be a positive integer")
        self._handler = handler
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=max_queue_size)
        self._closed = False
        self._lock = threading.Lock()
        self.dropped_count = 0
        self._worker = threading.Thread(
            target=self._run,
            name="alphaalgo-async-dispatcher",
            daemon=True,
        )
        self._worker.start()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP_SENTINEL:
                    return
                try:
                    self._handler(item)
                except Exception as exc:
                    logger.exception(
                        "Async handler failed for %s: %s",
                        item.get("event_id") if isinstance(item, dict) else "?",
                        exc,
                    )
            finally:
                self._queue.task_done()

    def __call__(self, event: dict[str, Any]) -> None:
        """Enqueue a verified event without blocking the HTTP request thread."""
        with self._lock:
            if self._closed:
                logger.warning(
                    "Async dispatcher closed; dropping %s",
                    event.get("event_id"),
                )
                self.dropped_count += 1
                return
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                self.dropped_count += 1
                logger.warning(
                    "Async dispatcher queue full (%d); dropping %s",
                    self._queue.maxsize,
                    event.get("event_id"),
                )

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until all currently queued items finish processing."""
        done = threading.Event()

        def _wait() -> None:
            self._queue.join()
            done.set()

        waiter = threading.Thread(target=_wait, daemon=True)
        waiter.start()
        return done.wait(timeout=timeout)

    def close(self, timeout: float = 5.0) -> None:
        """Drain queued events and stop the background worker cleanly."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._queue.put(_STOP_SENTINEL, timeout=timeout)
        except queue.Full:
            logger.warning("Async dispatcher queue full during shutdown")
            return
        self._worker.join(timeout=timeout)
