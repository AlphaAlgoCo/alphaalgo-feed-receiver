"""Configuration and environment self-check (`--doctor`) for the receiver.

Validates signing keys, port range, SQLite/JSONL writability, optional chat
sink configs, and UTC clock skew against the +/-300s replay window without
printing any secret material.
"""
from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any, Callable
import urllib.request

from .handlers import (
    _validate_discord_url,
    _validate_telegram_config,
)
from .security import ValidatedKeys, validate_signing_keys

_DEFAULT_CLOCK_URL = "https://alphaalgo.co"
_CLOCK_WARN_SECONDS = 60.0
_CLOCK_FAIL_SECONDS = 240.0


@dataclass(frozen=True)
class CheckResult:
    """Single diagnostic item reported by ``--doctor``."""

    name: str
    ok: bool
    detail: str
    warning: bool = False

    @property
    def badge(self) -> str:
        if not self.ok:
            return "FAIL"
        return "WARN" if self.warning else "PASS"


def parse_signing_secret(raw_secret: str) -> tuple[str, ...]:
    """Parse ``ALPHAALGO_SIGNING_SECRET`` (single or comma-separated)."""
    stripped = raw_secret.strip()
    if not stripped:
        raise ValueError(
            'Set ALPHAALGO_SIGNING_SECRET="whsec_..." (copy from Whop portal)'
        )
    parts = [part.strip() for part in stripped.split(",")]
    if any(not part for part in parts):
        raise ValueError(
            "ALPHAALGO_SIGNING_SECRET contains an empty entry between commas"
        )
    return tuple(parts)


def parse_signing_keys_json(raw_keys: str) -> dict[str, Any]:
    """Parse legacy ``ALPHAALGO_RECEIVER_KEYS_JSON`` into a key dict."""
    try:
        keys = json.loads(raw_keys) if raw_keys else {}
    except json.JSONDecodeError as exc:
        raise ValueError(
            "ALPHAALGO_RECEIVER_KEYS_JSON must be valid JSON mapping "
            "key_id -> whsec_..."
        ) from exc
    if not isinstance(keys, dict) or not keys:
        raise ValueError(
            'Set ALPHAALGO_SIGNING_SECRET="whsec_..." '
            '(or legacy ALPHAALGO_RECEIVER_KEYS_JSON)'
        )
    return keys


def resolve_signing_keys(
    *,
    raw_secret: str = "",
    raw_keys_json: str = "",
) -> ValidatedKeys:
    """Resolve and validate signing keys from env values (no ambiguity)."""
    has_secret = bool(raw_secret.strip())
    has_json = bool(raw_keys_json.strip())
    if has_secret and has_json:
        raise ValueError(
            "Set either ALPHAALGO_SIGNING_SECRET or "
            "ALPHAALGO_RECEIVER_KEYS_JSON, not both"
        )
    if has_secret:
        return validate_signing_keys(parse_signing_secret(raw_secret))
    if has_json:
        return validate_signing_keys(parse_signing_keys_json(raw_keys_json))
    raise ValueError(
        'Set ALPHAALGO_SIGNING_SECRET="whsec_..." (copy from Whop portal)'
    )


def _probe_remote_utc(url: str, timeout: float = 3.0) -> float:
    """Fetch HTTP Date header from a public HTTPS endpoint as Unix epoch."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "alphaalgo-feed-receiver/doctor"},
        method="HEAD",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw_date = resp.headers.get("Date")
    if not raw_date:
        raise ValueError("missing_date_header")
    return parsedate_to_datetime(raw_date).timestamp()


def _check_database_writable(db_path: str) -> CheckResult:
    if db_path == ":memory:":
        return CheckResult("sqlite_db", True, "in-memory SQLite (:memory:)")
    target = Path(db_path)
    existed = target.exists()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(target), timeout=5.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()
        if not existed:
            for suffix in ("", "-wal", "-shm"):
                p = Path(f"{target}{suffix}")
                if p.exists():
                    p.unlink()
        return CheckResult(
            "sqlite_db", True, f"writable WAL database path ({target})"
        )
    except Exception as exc:
        return CheckResult("sqlite_db", False, f"cannot open {target}: {exc}")


def _check_jsonl_writable(jsonl_path: str) -> CheckResult:
    target = Path(jsonl_path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if not os.access(target, os.W_OK):
                return CheckResult(
                    "jsonl_log", False, f"not writable ({target})"
                )
        elif not os.access(target.parent, os.W_OK):
            return CheckResult(
                "jsonl_log", False, f"directory not writable ({target.parent})"
            )
        return CheckResult("jsonl_log", True, f"writable path ({target})")
    except Exception as exc:
        return CheckResult("jsonl_log", False, f"invalid path {target}: {exc}")


def _check_clock_skew(
    *,
    clock_url: str,
    local_clock: Callable[[], float],
    remote_clock: Callable[[str], float],
) -> CheckResult:
    try:
        remote_ts = remote_clock(clock_url)
    except Exception as exc:
        return CheckResult(
            "clock_skew",
            True,
            f"skipped (could not reach {clock_url}: {type(exc).__name__})",
            warning=True,
        )
    skew = abs(local_clock() - remote_ts)
    if skew > _CLOCK_FAIL_SECONDS:
        return CheckResult(
            "clock_skew",
            False,
            f"local UTC clock off by {skew:.1f}s (exceeds safe margin "
            "for +/-300s replay window; sync NTP)",
        )
    if skew > _CLOCK_WARN_SECONDS:
        return CheckResult(
            "clock_skew",
            True,
            f"local UTC clock off by {skew:.1f}s (sync NTP to stay well "
            "inside +/-300s window)",
            warning=True,
        )
    return CheckResult(
        "clock_skew", True, f"local UTC clock within {skew:.1f}s of remote"
    )


def run_doctor(
    *,
    raw_secret: str = "",
    raw_keys_json: str = "",
    database: str,
    port: int,
    jsonl_log: str = "",
    discord_webhook: str = "",
    telegram_bot_token: str = "",
    telegram_chat_id: str = "",
    check_clock: bool = True,
    clock_url: str = _DEFAULT_CLOCK_URL,
    local_clock: Callable[[], float] | None = None,
    remote_clock: Callable[[str], float] | None = None,
) -> list[CheckResult]:
    """Run all local readiness checks and return structured results."""
    results: list[CheckResult] = []

    py = sys.version_info
    py_ver = f"{py.major}.{py.minor}.{py.micro}"
    if (py.major, py.minor) >= (3, 10):
        results.append(CheckResult("python", True, f"Python {py_ver}"))
    else:
        results.append(
            CheckResult(
                "python",
                True,
                f"Python {py_ver} (Python 3.10+ recommended)",
                warning=True,
            )
        )

    try:
        validated = resolve_signing_keys(
            raw_secret=raw_secret, raw_keys_json=raw_keys_json
        )
        if isinstance(validated, dict):
            key_ids = ", ".join(sorted(validated.keys()))
            detail = f"{len(validated)} valid key(s) configured: {key_ids}"
        else:
            detail = (
                f"{len(validated)} valid signing secret(s) configured "
                "(ALPHAALGO_SIGNING_SECRET)"
            )
        results.append(CheckResult("signing_keys", True, detail))
    except ValueError as exc:
        results.append(CheckResult("signing_keys", False, str(exc)))

    if 1 <= port <= 65535:
        results.append(CheckResult("port", True, f"port {port}"))
    else:
        results.append(
            CheckResult(
                "port", False, f"invalid port {port} (expected 1..65535)"
            )
        )

    results.append(_check_database_writable(database))

    if jsonl_log:
        results.append(_check_jsonl_writable(jsonl_log))

    if discord_webhook:
        try:
            _validate_discord_url(discord_webhook)
            results.append(
                CheckResult(
                    "discord_sink", True, "valid HTTPS Discord webhook URL"
                )
            )
        except ValueError as exc:
            results.append(CheckResult("discord_sink", False, str(exc)))

    if telegram_bot_token or telegram_chat_id:
        if bool(telegram_bot_token) != bool(telegram_chat_id):
            results.append(
                CheckResult(
                    "telegram_sink",
                    False,
                    "both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required",
                )
            )
        else:
            try:
                _validate_telegram_config(telegram_bot_token, telegram_chat_id)
                results.append(
                    CheckResult(
                        "telegram_sink",
                        True,
                        "valid Telegram Bot token and chat_id",
                    )
                )
            except ValueError as exc:
                results.append(CheckResult("telegram_sink", False, str(exc)))

    if check_clock:
        results.append(
            _check_clock_skew(
                clock_url=clock_url,
                local_clock=local_clock or time.time,
                remote_clock=remote_clock or _probe_remote_utc,
            )
        )

    return results


def format_doctor_report(results: list[CheckResult]) -> str:
    """Format diagnostic checks into a concise, secret-free terminal report."""
    lines = ["AlphaAlgo Feed Receiver — Configuration Doctor", "-" * 52]
    for item in results:
        lines.append(f"[{item.badge}] {item.name:<15} {item.detail}")
    failed = sum(1 for r in results if not r.ok)
    warned = sum(1 for r in results if r.ok and r.warning)
    lines.append("-" * 52)
    if failed:
        lines.append(f"Result: FAILED ({failed} error(s), {warned} warning(s))")
    elif warned:
        lines.append(f"Result: READY WITH WARNINGS ({warned} warning(s))")
    else:
        lines.append("Result: READY (all checks passed)")
    return "\n".join(lines)
