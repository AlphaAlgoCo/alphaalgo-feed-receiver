"""CLI entry point for the AlphaAlgo Developer Feed v3 receiver."""
from __future__ import annotations

import argparse
import json
import logging
import os
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from .handlers import (
    EventHandler,
    discord_webhook_handler,
    dispatch_handlers,
    jsonl_file_handler,
    on_verified_event,
)
from .receiver import WebhookReceiver


class _QuietHandler(WSGIRequestHandler):
    """Suppress per-request access logs to avoid noisy stdout."""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Handle concurrent deliveries so slow hooks do not block /events."""

    daemon_threads = True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the AlphaAlgo Developer Feed v3 signed webhook receiver "
            "(log-only, never places brokerage orders)."
        )
    )
    parser.add_argument(
        "--database",
        default=os.environ.get("ALPHAALGO_DB_PATH", "./receipts.db"),
        help="Path to SQLite receipts database (default: ./receipts.db)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("ALPHAALGO_HOST", "127.0.0.1"),
        help="Bind host (default: 127.0.0.1; terminate TLS via reverse proxy)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("ALPHAALGO_PORT", "9091")),
        help="Bind port (default: 9091)",
    )
    parser.add_argument(
        "--jsonl-log",
        default=os.environ.get("ALPHAALGO_JSONL_LOG", ""),
        help="Optional path to append verified events as JSONL",
    )
    parser.add_argument(
        "--discord-webhook",
        default=os.environ.get("DISCORD_WEBHOOK_URL", ""),
        help="Optional HTTPS Discord webhook URL for read-only alerts",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    raw_keys = os.environ.get("ALPHAALGO_RECEIVER_KEYS_JSON", "")
    try:
        keys = json.loads(raw_keys) if raw_keys else {}
    except json.JSONDecodeError:
        parser.error(
            "ALPHAALGO_RECEIVER_KEYS_JSON must be valid JSON mapping "
            "key_id -> whsec_..."
        )
    if not isinstance(keys, dict) or not keys:
        parser.error(
            'Set ALPHAALGO_RECEIVER_KEYS_JSON, e.g. \'{"v1": "whsec_..."}\''
        )

    # Always run `on_verified_event` (edit handlers.py to add custom logic),
    # plus any optional CLI-configured read-only sinks.
    handlers: list[EventHandler] = [on_verified_event]
    if args.jsonl_log:
        handlers.append(jsonl_file_handler(args.jsonl_log))
    if args.discord_webhook:
        handlers.append(discord_webhook_handler(args.discord_webhook))

    try:
        app = WebhookReceiver(
            args.database,
            keys,
            on_event=dispatch_handlers(handlers),
        )
    except ValueError as exc:
        parser.error(f"Invalid receiver configuration: {exc}")

    logging.getLogger("alphaalgo_receiver").info(
        "Listening on http://%s:%d/events (healthz: /healthz, db: %s)",
        args.host,
        args.port,
        args.database,
    )
    with make_server(
        args.host,
        args.port,
        app,
        server_class=_ThreadingWSGIServer,
        handler_class=_QuietHandler,
    ) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            app.close()


if __name__ == "__main__":
    main()
