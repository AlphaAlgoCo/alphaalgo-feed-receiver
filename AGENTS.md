# AGENTS.md — AI Assistant Guide for `alphaalgo-feed-receiver`

This repository is the official open-source, **read-only** webhook receiver starter kit for the [AlphaAlgo Developer Feed](https://alphaalgo.co) (`schema_version: 3`).

If you are an AI coding assistant (Cursor, Claude Code, Codex, Antigravity, etc.) helping a subscriber understand, customize, test, or deploy this repository, follow these rules strictly.

---

## 1. Repository Architecture

- `alphaalgo_receiver/security.py`: Standard Webhooks v1 raw-byte HMAC-SHA256 verification (`Webhook-Id`, `Webhook-Timestamp`, `Webhook-Signature`, optional `Webhook-Key-Id`), ±300s replay guard, single/multi-secret verification (`ALPHAALGO_SIGNING_SECRET`) and legacy `ALPHAALGO_RECEIVER_KEYS_JSON`. **Do not weaken or bypass.**
- `alphaalgo_receiver/receiver.py`: Threaded WSGI app (`GET /healthz`, `POST /events`), strict 64 KiB body & JSON bounds (`NaN`/`Infinity` rejected), atomic SQLite WAL deduplication (`200 duplicate:true`, `409 Conflict` on hash mismatch).
- `alphaalgo_receiver/handlers.py`: **Primary customization point.** Edit `on_verified_event(event)` or wire built-in sinks (`jsonl_file_handler`, `discord_webhook_handler`, `telegram_bot_handler`, `dispatch_handlers`, `AsyncEventDispatcher`).
- `alphaalgo_receiver/cli.py`: CLI flags, env-var bindings, and threaded server lifecycle.
- `examples/paper_ledger.py`: Read-only local position state tracker (`PaperLedger`) demonstrating monotonic `trade_revision` tracking across 1-leg, 2-leg, and 4-leg lifecycles.
- `scripts/send_mock_event.py`: Signed synthetic event generator and full lifecycle/edge-case scenario replayer (`--scenario full_demo`).
- `docs/SCHEMA_V3.md`: Authoritative Schema v3 field reference, JSON examples, and consumer safety invariants. **Always read this before inventing or assuming field names.**

---

## 2. Hard Invariants (Never Violate)

1. **Preserve the Read-Only Core**: Keep `alphaalgo_receiver/` strictly stdlib-only and free of brokerage SDKs or order-placement code. If a user asks to build their own downstream integration, read `docs/SCHEMA_V3.md` first and respect their explicit instructions and risk controls in their own separate code.
2. **Zero Third-Party Dependencies**: Do not add external packages to `pyproject.toml` or `alphaalgo_receiver/`. Keep pure Python 3.10+ standard library.
3. **Never Break Raw-Byte Verification**: Always verify HMAC signatures on exact raw UTF-8 HTTP request bytes before `json.loads`. Never re-serialize JSON before verification.
4. **Always Inspect `event["instrument"]["legs"]`**: Top-level `event["option_symbol"]` is `null` for `vertical_credit_spread` (2-leg) and `iron_butterfly` (4-leg). Never assume `option_symbol` is a string.
5. **Gate on `record_kind` and `instrument["complete"]`**:
   - Check `event.get("record_kind") == "fill"` to distinguish live broker fills from `settlement_observation` or `non_execution_close`.
   - Check `event.get("instrument", {}).get("complete") is True` before acting on legs.
6. **Enforce Monotonic `trade_revision`**: Key stateful tracking by `event["trade_ref"]` and ignore any event where `trade_revision <= last_applied_revision`.
7. **Never Leak Secrets in Logs**: Never log `whsec_...` signing secrets, Discord webhook URLs, or Telegram bot tokens (even inside HTTP exception strings).
8. **Keep HTTP `200 OK` Fast**: Wrap any slow outbound network/DB handler in `AsyncEventDispatcher` (or pass `--async-handlers`) so upstream webhook deliveries never time out.

---

## 3. Coding Style & Local Verification

- Keep Python lines `<= 80` characters (matches `[tool.ruff] line-length = 80` in `pyproject.toml`).
- Avoid duplicate helpers; reuse `format_event_summary`, `describe_contract`, `dispatch_handlers`, and `serve_receiver`.
- Run the full test suite before finishing any change:

```bash
python3 -m unittest discover -s tests -q
```

- Test end-to-end webhook behavior locally with the full lifecycle replay:

```bash
# Terminal 1 (with ALPHAALGO_SIGNING_SECRET exported)
python3 examples/paper_ledger.py --serve --port 9091

# Terminal 2
python3 scripts/send_mock_event.py --scenario full_demo --delay 0.1
```

For step-by-step downstream integration recipes, see `.agents/skills/alphaalgo-feed-integration/SKILL.md`.
