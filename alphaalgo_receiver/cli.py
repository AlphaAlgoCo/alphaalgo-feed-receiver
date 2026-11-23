"""CLI entry point for the AlphaAlgo Developer Feed v3 receiver."""
from __future__ import annotations

import argparse
import json
import logging
import os
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from .handlers import (
    AsyncEventDispatcher,
    EventHandler,
    discord_webhook_handler,
    dispatch_handlers,
    jsonl_file_handler,
    on_verified_event,
    telegram_bot_handler,
)
from .receiver import WebhookReceiver


def _env_flag(name: str) -> bool:
    """Parse a boolean environment variable (1/true/yes/on)."""
    return os.environ.get(name, "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _default_port() -> int:
    """Resolve bind port: ALPHAALGO_PORT -> PaaS PORT -> 9091."""
    raw = os.environ.get("ALPHAALGO_PORT") or os.environ.get("PORT") or "9091"
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ValueError(
            f"Invalid port environment value {raw!r}; expected integer 1..65535"
        ) from exc


class _QuietHandler(WSGIRequestHandler):
    """Suppress per-request access logs to avoid noisy stdout."""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Handle concurrent deliveries so slow hooks do not block /events."""

    daemon_threads = True


def serve_receiver(app: WebhookReceiver, host: str, port: int) -> None:
    """Serve a WebhookReceiver over threaded HTTP until interrupted."""
    with make_server(
        host,
        port,
        app,
        server_class=_ThreadingWSGIServer,
        handler_class=_QuietHandler,
    ) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


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
        default=None,
        help="Bind port (default: ALPHAALGO_PORT, then PORT, then 9091)",
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
        "--telegram-bot-token",
        default=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
        help="Optional Telegram Bot API token for read-only alerts",
    )
    parser.add_argument(
        "--telegram-chat-id",
        default=os.environ.get("TELEGRAM_CHAT_ID", ""),
        help="Telegram chat ID paired with --telegram-bot-token",
    )
    parser.add_argument(
        "--async-handlers",
        action="store_true",
        default=_env_flag("ALPHAALGO_ASYNC_HANDLERS"),
        help=(
            "Run downstream handlers on a background worker thread so "
            "POST /events returns 200 OK immediately"
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )
    return parser


def _build_event_pipeline(
    args: argparse.Namespace,
) -> tuple[EventHandler, AsyncEventDispatcher | None]:
    """Assemble verified-event handlers and optional async background queue."""
    if bool(args.telegram_bot_token) != bool(args.telegram_chat_id):
        raise ValueError(
            "Both --telegram-bot-token and --telegram-chat-id must be set "
            "together"
        )

    # Always run `on_verified_event` (edit handlers.py to add custom logic),
    # plus any optional CLI-configured read-only sinks.
    handlers: list[EventHandler] = [on_verified_event]
    if args.jsonl_log:
        handlers.append(jsonl_file_handler(args.jsonl_log))
    if args.discord_webhook:
        handlers.append(discord_webhook_handler(args.discord_webhook))
    if args.telegram_bot_token and args.telegram_chat_id:
        handlers.append(
            telegram_bot_handler(
                args.telegram_bot_token, args.telegram_chat_id
            )
        )

    pipeline = dispatch_handlers(handlers)
    if args.async_handlers:
        dispatcher = AsyncEventDispatcher(pipeline)
        return dispatcher, dispatcher
    return pipeline, None


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.port is None:
        try:
            args.port = _default_port()
        except ValueError as exc:
            parser.error(str(exc))

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

    async_dispatcher: AsyncEventDispatcher | None = None
    try:
        on_event, async_dispatcher = _build_event_pipeline(args)
        app = WebhookReceiver(
            args.database,
            keys,
            on_event=on_event,
        )
    except ValueError as exc:
        if async_dispatcher is not None:
            async_dispatcher.close()
        parser.error(f"Invalid receiver configuration: {exc}")

    logging.getLogger("alphaalgo_receiver").info(
        "Listening on http://%s:%d/events (healthz: /healthz, db: %s, "
        "async=%s)",
        args.host,
        args.port,
        args.database,
        args.async_handlers,
    )
    try:
        serve_receiver(app, args.host, args.port)
    finally:
        if async_dispatcher is not None:
            async_dispatcher.close()
        app.close()


if __name__ == "__main__":
    main()
