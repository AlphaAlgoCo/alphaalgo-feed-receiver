"""Durable, idempotent WSGI webhook receiver for AlphaAlgo Feed v3.

Responsibilities:
  1. Parse strict HTTP bounds (method, route, content-type, max body size).
  2. Verify Standard Webhooks v1 signature on exact raw HTTP body bytes.
  3. Atomically persist and deduplicate receipts in SQLite (WAL mode).
  4. Invoke `on_event(event)` once per unique verified event.

To customize downstream behavior, edit `alphaalgo_receiver/handlers.py` or
pass your own `on_event` callable to `WebhookReceiver(...)`.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from typing import Any, Callable, Mapping

from .handlers import EventHandler, on_verified_event
from .security import FeedSecurityError, validate_signing_keys, verify_event

logger = logging.getLogger("alphaalgo_receiver")

SCHEMA_VERSION = 3
MAX_BODY_BYTES = 65536

_STATUS_PHRASES = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    409: "Conflict",
    503: "Service Unavailable",
}


def _reject_json_constant(token: str) -> Any:
    """Reject non-standard JSON tokens such as NaN and Infinity."""
    raise ValueError(f"invalid_json_constant:{token}")


class WebhookReceiver:
    """Thread-safe WSGI receiver with SQLite WAL idempotency."""

    def __init__(
        self,
        database: str | os.PathLike[str],
        keys: Mapping[str, str | bytes],
        *,
        on_event: EventHandler | None = on_verified_event,
        clock: Callable[[], float] | None = None,
        max_age: int = 300,
    ) -> None:
        # Fail fast if any configured key_id or whsec_ secret is malformed.
        self.keys = validate_signing_keys(keys)
        self.on_event = on_event
        self.clock = clock
        self.max_age = max_age
        self.lock = threading.Lock()

        self.connection = sqlite3.connect(
            str(database), timeout=30.0, check_same_thread=False
        )
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                event_id    TEXT PRIMARY KEY,
                trade_ref   TEXT,
                event_kind  TEXT,
                strategy_id TEXT,
                received_at REAL NOT NULL,
                body_sha256 TEXT NOT NULL,
                body        BLOB NOT NULL
            )
            """
        )
        self.connection.commit()
        if str(database) != ":memory:":
            os.chmod(database, 0o600)

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self.connection.close()

    def _persist_receipt(
        self,
        event_id: str,
        event: Mapping[str, Any],
        body: bytes,
        now: float,
    ) -> str:
        """Atomically persist receipt; return inserted/duplicate/conflict."""
        digest = hashlib.sha256(body).hexdigest()
        with self.lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                prior = self.connection.execute(
                    "SELECT body_sha256 FROM receipts WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if prior is not None:
                    self.connection.rollback()
                    return "duplicate" if prior[0] == digest else "conflict"

                self.connection.execute(
                    "INSERT INTO receipts ("
                    "event_id, trade_ref, event_kind, strategy_id, "
                    "received_at, body_sha256, body"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        str(event.get("trade_ref", "")),
                        str(event.get("event_kind", "")),
                        str(event.get("strategy_id", "")),
                        float(now),
                        digest,
                        body,
                    ),
                )
                self.connection.commit()
                return "inserted"
            except BaseException:
                self.connection.rollback()
                raise

    def receive(
        self,
        body: bytes,
        headers: Mapping[str, str],
    ) -> tuple[int, dict[str, Any]]:
        """Verify, deduplicate, persist, and dispatch a single webhook POST."""
        if not isinstance(body, bytes) or len(body) > MAX_BODY_BYTES:
            return 400, {"error": "invalid_request"}
        try:
            now = self.clock() if self.clock else time.time()
            event_id = verify_event(
                body, headers, self.keys, now=now, max_age=self.max_age
            )
            event = json.loads(
                body.decode("utf-8"), parse_constant=_reject_json_constant
            )
            if (
                not isinstance(event, dict)
                or event.get("event_id") != event_id
                or type(event.get("schema_version")) is not int
                or event.get("schema_version") != SCHEMA_VERSION
            ):
                return 400, {"error": "invalid_event_envelope"}

            outcome = self._persist_receipt(event_id, event, body, now)
            if outcome == "conflict":
                return 409, {"error": "event_id_collision"}
            if outcome == "duplicate":
                return 200, {
                    "accepted": True,
                    "duplicate": True,
                    "execution": "disabled",
                }

            # Invoke the user's downstream handler only after durable commit.
            if self.on_event is not None:
                try:
                    self.on_event(event)
                except Exception as exc:
                    logger.exception(
                        "on_event hook failed for %s: %s", event_id, exc
                    )

            return 200, {
                "accepted": True,
                "duplicate": False,
                "execution": "disabled",
            }
        except FeedSecurityError:
            return 401, {"error": "signature_rejected"}
        except (ValueError, UnicodeError, TypeError):
            return 400, {"error": "invalid_event_envelope"}

    def _read_event_request(
        self, environ: Mapping[str, Any]
    ) -> tuple[bytes, dict[str, str]]:
        """Extract raw JSON body bytes and normalized HTTP headers from WSGI."""
        size = int(environ.get("CONTENT_LENGTH", ""))
        if (
            size < 0
            or size > MAX_BODY_BYTES
            or environ.get("HTTP_TRANSFER_ENCODING")
        ):
            raise ValueError("invalid_content_length")

        raw_ct = environ.get("CONTENT_TYPE", "")
        if raw_ct.split(";")[0].strip().lower() != "application/json":
            raise ValueError("invalid_content_type")

        body = environ["wsgi.input"].read(size)
        if len(body) != size:
            raise ValueError("truncated_body")

        headers = {
            key[5:].lower().replace("_", "-"): value
            for key, value in environ.items()
            if key.startswith("HTTP_")
        }
        return body, headers

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: Callable[..., Any],
    ) -> list[bytes]:
        path = environ.get("PATH_INFO")
        method = environ.get("REQUEST_METHOD")

        if path == "/healthz" and method == "GET":
            status = 200
            result: dict[str, Any] = {
                "service": "alphaalgo-feed-receiver",
                "schema_version": SCHEMA_VERSION,
                "execution": "disabled",
            }
        elif path == "/events" and method == "POST":
            try:
                body, headers = self._read_event_request(environ)
                status, result = self.receive(body, headers)
            except ValueError:
                status, result = 400, {"error": "invalid_request"}
            except Exception:
                logger.exception("Unexpected receiver error")
                status, result = 503, {"error": "receiver_unavailable"}
        else:
            status, result = 404, {"error": "route_not_found"}

        payload = json.dumps(result).encode("utf-8")
        phrase = _STATUS_PHRASES[status]
        start_response(
            f"{status} {phrase}",
            [
                ("Content-Type", "application/json"),
                ("Cache-Control", "no-store"),
                ("Content-Length", str(len(payload))),
            ],
        )
        return [payload]
