"""Standard Webhooks v1 HMAC-SHA256 signing and verification (Feed v3).

Every AlphaAlgo Developer Feed webhook signs the exact raw UTF-8 HTTP body
bytes using the Standard Webhooks v1 format:

    signed_payload = f"{Webhook-Id}.{Webhook-Timestamp}.{raw_body}"
    signature      = "v1," + base64(HMAC_SHA256(secret_bytes, signed_payload))

Always verify against the raw request bytes before parsing JSON.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import secrets
import time
from typing import Callable, Mapping, Sequence, Union

SigningKeys = Union[
    str, bytes, Sequence[Union[str, bytes]], Mapping[str, Union[str, bytes]]
]
ValidatedKeys = Union[dict[str, bytes], tuple[bytes, ...]]


class FeedSecurityError(ValueError):
    """Fixed, non-sensitive error codes raised during webhook verification."""


_EVENT_ID_RE = re.compile(r"[A-Za-z0-9_.:\-]{1,256}\Z")
_KEY_ID_RE = re.compile(r"[A-Za-z0-9_\-]{1,128}\Z")
_MIN_KEY_BYTES = 32
_MAX_SIGNING_KEYS = 16
_MAX_SIGNATURE_HEADER_LEN = 2048
_MAX_TIMESTAMP_DIGITS = 16


def generate_signing_secret() -> str:
    """Generate a Standard Webhooks signing secret (`whsec_<base64>`)."""
    raw = secrets.token_bytes(_MIN_KEY_BYTES)
    return "whsec_" + base64.b64encode(raw).decode("ascii")


def _secret_bytes(secret: str | bytes) -> bytes:
    """Decode and validate a 32+ byte signing secret."""
    if isinstance(secret, bytes):
        if len(secret) < _MIN_KEY_BYTES:
            raise FeedSecurityError("invalid_signing_key")
        return secret
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise FeedSecurityError("invalid_signing_key")
    try:
        key = base64.b64decode(secret[6:], validate=True)
    except (ValueError, TypeError):
        raise FeedSecurityError("invalid_signing_key") from None
    if len(key) < _MIN_KEY_BYTES:
        raise FeedSecurityError("invalid_signing_key")
    return key


def validate_signing_keys(keys: SigningKeys) -> ValidatedKeys:
    """Validate configured signing secret(s) or key_id mapping at startup."""
    if isinstance(keys, Mapping):
        if not keys:
            raise ValueError("receiver_signing_keys_required")
        if len(keys) > _MAX_SIGNING_KEYS:
            raise ValueError("too_many_signing_keys")
        validated: dict[str, bytes] = {}
        for key_id, secret in keys.items():
            if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
                raise FeedSecurityError("invalid_key_id")
            validated[key_id] = _secret_bytes(secret)
        return validated

    if isinstance(keys, (str, bytes)):
        if not keys:
            raise ValueError("receiver_signing_keys_required")
        return (_secret_bytes(keys),)

    if isinstance(keys, bytearray):
        raise FeedSecurityError("invalid_signing_key")

    if isinstance(keys, Sequence):
        if not keys:
            raise ValueError("receiver_signing_keys_required")
        if len(keys) > _MAX_SIGNING_KEYS:
            raise ValueError("too_many_signing_keys")
        deduped = tuple(
            dict.fromkeys(_secret_bytes(secret) for secret in keys)
        )
        return deduped

    raise ValueError("receiver_signing_keys_required")


def _compute_signature(
    event_id: str,
    attempt_timestamp: int,
    body: bytes,
    secret: str | bytes,
) -> str:
    """Compute a Standard Webhooks v1 HMAC-SHA256 signature string."""
    if not isinstance(event_id, str) or not _EVENT_ID_RE.fullmatch(event_id):
        raise FeedSecurityError("invalid_event_id")
    if (
        not isinstance(attempt_timestamp, int)
        or isinstance(attempt_timestamp, bool)
        or attempt_timestamp < 0
    ):
        raise FeedSecurityError("invalid_timestamp")
    if not isinstance(body, bytes):
        raise FeedSecurityError("invalid_body")

    ts = str(attempt_timestamp)
    signed = event_id.encode("ascii") + b"." + ts.encode("ascii") + b"." + body
    mac = hmac.new(_secret_bytes(secret), signed, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode("ascii")


def sign_event(
    event_id: str,
    attempt_timestamp: int,
    body: bytes,
    secret: str | bytes,
    key_id: str = "v1",
) -> dict[str, str]:
    """Build Standard Webhooks v1 headers for raw UTF-8 JSON bytes."""
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise FeedSecurityError("invalid_key_id")
    signature = _compute_signature(event_id, attempt_timestamp, body, secret)
    return {
        "Webhook-Id": event_id,
        "Webhook-Timestamp": str(attempt_timestamp),
        "Webhook-Signature": signature,
        "Webhook-Key-Id": key_id,
    }


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Lowercase header names and reject duplicate header keys."""
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        lower = str(name).lower()
        if lower in normalized:
            raise FeedSecurityError("duplicate_header")
        normalized[lower] = str(value)
    return normalized


def verify_event(
    body: bytes,
    headers: Mapping[str, str],
    keys: SigningKeys,
    *,
    now: float | None = None,
    max_age: int = 300,
    consume: Callable[[str], bool] | None = None,
) -> str:
    """Verify raw bytes, timestamp freshness, and HMAC-SHA256 signature.

    Args:
        body: Exact raw HTTP request body bytes.
        headers: HTTP request headers (matched case-insensitively).
        keys: A single ``whsec_...`` secret, a sequence of secrets (for
            key-ID-agnostic verification/rotation), or a legacy mapping of
            ``key_id -> whsec_...`` secrets.
        now: Optional Unix timestamp (seconds) for deterministic testing.
        max_age: Allowed clock skew / replay window in seconds (default: 300).
        consume: Optional atomic dedup callback returning False on duplicates.

    Returns:
        The verified ``event_id`` from ``Webhook-Id``.
    """
    normalized = _normalize_headers(headers)
    event_id = normalized.get("webhook-id", "")
    timestamp = normalized.get("webhook-timestamp", "")

    if (
        not timestamp.isascii()
        or not timestamp.isdigit()
        or len(timestamp) > _MAX_TIMESTAMP_DIGITS
    ):
        raise FeedSecurityError("invalid_timestamp")

    current = time.time() if now is None else now
    if (
        not isinstance(current, (int, float))
        or isinstance(current, bool)
        or not math.isfinite(current)
        or not isinstance(max_age, int)
        or isinstance(max_age, bool)
        or max_age <= 0
    ):
        raise FeedSecurityError("invalid_clock")
    if abs(current - int(timestamp)) > max_age:
        raise FeedSecurityError("stale_timestamp")

    supplied = normalized.get("webhook-signature", "")
    if not supplied.isascii() or len(supplied) > _MAX_SIGNATURE_HEADER_LEN:
        raise FeedSecurityError("invalid_signature")

    ts_int = int(timestamp)
    if isinstance(keys, Mapping):
        key_id = normalized.get("webhook-key-id", "")
        if key_id not in keys:
            raise FeedSecurityError("unknown_key_id")
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise FeedSecurityError("invalid_key_id")
        expected_sigs = (
            _compute_signature(event_id, ts_int, body, keys[key_id]),
        )
    else:
        try:
            validated = validate_signing_keys(keys)
        except ValueError:
            raise FeedSecurityError("invalid_signing_key") from None
        assert isinstance(validated, tuple)
        expected_sigs = tuple(
            _compute_signature(event_id, ts_int, body, secret)
            for secret in validated
        )

    # Standard Webhooks allows multiple space-separated signatures; accept if
    # any candidate matches any configured secret in constant time.
    candidates = [c for c in supplied.split(" ") if c]
    if not candidates:
        raise FeedSecurityError("invalid_signature")
    matched = False
    for expected in expected_sigs:
        for candidate in candidates:
            if hmac.compare_digest(candidate, expected):
                matched = True
    if not matched:
        raise FeedSecurityError("invalid_signature")

    if consume is not None and not consume(event_id):
        raise FeedSecurityError("duplicate_event")

    return event_id
