"""AlphaAlgo Developer Feed — Signed Webhook Receiver (Schema v3).

Research and execution telemetry starter kit. Never places brokerage orders.
"""
from .handlers import (
    dispatch_handlers,
    discord_webhook_handler,
    format_event_summary,
    jsonl_file_handler,
    on_verified_event,
)
from .receiver import WebhookReceiver
from .security import (
    FeedSecurityError,
    generate_signing_secret,
    sign_event,
    validate_signing_keys,
    verify_event,
)

__all__ = [
    "FeedSecurityError",
    "WebhookReceiver",
    "discord_webhook_handler",
    "dispatch_handlers",
    "format_event_summary",
    "generate_signing_secret",
    "jsonl_file_handler",
    "on_verified_event",
    "sign_event",
    "validate_signing_keys",
    "verify_event",
]
