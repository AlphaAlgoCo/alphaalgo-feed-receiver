---
name: alphaalgo-feed-integration
description: Build, customize, test, and debug downstream integrations for the AlphaAlgo Developer Feed v3 signed webhook receiver without guessing field names or violating schema invariants.
---

# AlphaAlgo Developer Feed v3 — AI Integration Skill

Use this skill whenever helping a user customize `alphaalgo-feed-receiver`, write a new event handler, build a local analytics/alerting pipeline, or troubleshoot webhook signature/schema issues.

## 1. Authoritative References (Read First)

- Protocol & field contract: `docs/SCHEMA_V3.md`
- Core customization hook: `alphaalgo_receiver/handlers.py` (`on_verified_event`)
- Reference state machine: `examples/paper_ledger.py` (`PaperLedger`)
- Local replay tool: `scripts/send_mock_event.py` (`--scenario full_demo`)

Never invent field names—verify every field against `docs/SCHEMA_V3.md`.

## 2. Fast Integration Recipes

### Recipe A: Filter by Strategy and Complete Fills

```python
def on_verified_event(event: dict) -> None:
    if event.get("strategy_id") not in {"S608", "S623", "S662"}:
        return
    if event.get("record_kind") != "fill":
        return
    inst = event.get("instrument") or {}
    if not inst.get("complete"):
        return
    for leg in inst["legs"]:
        print(
            event["trade_ref"],
            event["event_kind"],
            leg["role"],
            leg["option_symbol"],
            leg["entry_side"],
        )
```

### Recipe B: Keep `/events` Fast Under Slow Outbound Sinks

Always wrap slow I/O (HTTP webhooks, databases, Slack/Telegram/Discord) in `AsyncEventDispatcher` or run the CLI with `--async-handlers`:

```python
from alphaalgo_receiver import (
    AsyncEventDispatcher,
    WebhookReceiver,
    dispatch_handlers,
    jsonl_file_handler,
    telegram_bot_handler,
)

pipeline = dispatch_handlers([
    jsonl_file_handler("./events.jsonl"),
    telegram_bot_handler(bot_token, chat_id),
])
async_sink = AsyncEventDispatcher(pipeline, max_queue_size=1000)
app = WebhookReceiver("./receipts.db", keys, on_event=async_sink)
```

Remember to call `async_sink.close()` before `app.close()` on shutdown so queued events flush cleanly.

### Recipe C: Maintain Stateful Positions Across Lifecycles

Reuse `examples/paper_ledger.py` (`PaperLedger`) as the blueprint:
1. Key state by `trade_ref`.
2. Ignore events where `trade_revision <= state.last_revision`.
3. Update open/closed status from `event_kind` (`entry`, `entry_update`, `partial_exit`, `exit`) and `remaining_quantity`.
4. Flag `record_kind != "fill"`, `instrument["complete"] is False`, and `now > expires_at` explicitly rather than silently dropping audit visibility.

## 3. Troubleshooting Checklist

| Symptom | Most Likely Cause | Fix |
| :--- | :--- | :--- |
| `401 signature_rejected` | Body parsed & re-serialized before verification, wrong `whsec_` secret, or clock skew > ±300s | Verify exact raw bytes; check `ALPHAALGO_SIGNING_SECRET` (or `ALPHAALGO_RECEIVER_KEYS_JSON` key ID if using legacy mode); sync NTP clock |
| `400 invalid_event_envelope` | `Content-Type` not `application/json`, body > 64 KiB, `schema_version != 3`, or `Webhook-Id != event_id` | Inspect HTTP proxy framing (avoid chunked encoding or body rewrites) |
| `409 event_id_collision` | Same `event_id` sent with mutated bytes | Expected protection; ensure synthetic test events use distinct `source_event_id` |
| `option_symbol` is `None` | Event is a 2-leg `vertical_credit_spread` or 4-leg `iron_butterfly` | Always iterate `event["instrument"]["legs"]` |
| Missed notifications on restart | In-memory handler without durable replay | Rebuild state from `receipts.db` via `examples/paper_ledger.py --from-db` |

## 4. Verification Before Returning Code to the User

1. Run `python3 -m unittest discover -s tests -q`.
2. Verify any new handler against `scripts/send_mock_event.py --scenario full_demo --delay 0`.
3. Confirm no secrets (`whsec_`, bot tokens, webhook URLs) are printed or committed.
