# AlphaAlgo Developer Feed — Signed Webhook Receiver (v3)

Official open-source reference receiver for the **[AlphaAlgo](https://alphaalgo.co)** Signed Developer Webhook Feed (`schema_version: 3`).

Built with **zero third-party dependencies** (pure Python 3.10+ standard library), this starter kit handles:

- **Raw-byte HMAC-SHA256 verification** following the [Standard Webhooks v1](https://www.standardwebhooks.com/) signing convention (`Webhook-Id`, `Webhook-Timestamp`, `Webhook-Signature`, `Webhook-Key-Id`)
- **Replay protection** (strict ±300s timestamp window)
- **Zero-downtime key rotation** (map multiple `key_id -> whsec_...` secrets simultaneously)
- **Durable SQLite (WAL) idempotency** — deduplicates retries by `event_id` and rejects mismatched payload collisions with `409 Conflict`
- **Unified Schema v3 parsing** across all 3 first-class `instrument.kind` types (`single_option`, `vertical_credit_spread`, `iron_butterfly`) with uniform `instrument.legs[]`
- **Clear extension point (`alphaalgo_receiver/handlers.py`)** — edit `on_verified_event(event)` or attach built-in JSONL / Discord read-only sinks

> **Research & Telemetry Only — No Brokerage Execution:** This repository is strictly a read-only webhook receiver and logging starter kit. It never connects to any brokerage API and never places orders. Subscribers retain sole control over their own infrastructure, trading decisions, and risk.

---

## Project Layout

```text
alphaalgo_receiver/
  handlers.py   <-- START HERE: edit `on_verified_event(event)` to add your logic
  receiver.py   <-- HTTP / WSGI server + SQLite WAL deduplication
  security.py   <-- Standard Webhooks v1 HMAC-SHA256 signing & verification
  cli.py        <-- CLI flags & wiring (`python3 -m alphaalgo_receiver`)
scripts/
  send_mock_event.py  <-- Send locally signed mock v3 events (1-leg, 2-leg, 4-leg)
tests/
  test_receiver.py    <-- Unit tests for security, HTTP bounds, SQLite, handlers
```

---

## Quickstart (60 Seconds)

### 1. Clone & run tests

```bash
git clone https://github.com/AlphaAlgoCo/alphaalgo-feed-receiver.git
cd alphaalgo-feed-receiver
python3 -m unittest discover -s tests -q
```

### 2. Start the receiver with a local test key

For production, copy your `key_id` and `whsec_...` signing secret from the **AlphaAlgo Developer Feed** portal inside your [Whop membership](https://whop.com/alphaalgoco/).

For local testing:

```bash
export ALPHAALGO_RECEIVER_KEYS_JSON='{"v1":"'"$(python3 -c 'from alphaalgo_receiver import generate_signing_secret; print(generate_signing_secret())')"'"}'

python3 -m alphaalgo_receiver \
  --database ./receipts.db \
  --jsonl-log ./events.jsonl \
  --port 9091
```

### 3. Send signed mock events (all 3 instrument kinds)

In a second terminal (with the same `ALPHAALGO_RECEIVER_KEYS_JSON` exported):

```bash
# 1-leg equity option fill (single_option)
python3 scripts/send_mock_event.py --kind equity_entry

# 2-leg $SPX vertical credit spread fill (vertical_credit_spread, CPS)
python3 scripts/send_mock_event.py --kind spx_spread_entry

# 4-leg $SPX iron butterfly fill (iron_butterfly, IBF)
python3 scripts/send_mock_event.py --kind spx_ibf_entry
```

You should see:

```text
HTTP 200: {"accepted": true, "duplicate": false, "execution": "disabled"}
```

---

## Where to Add Your Own Event Logic

Open **[`alphaalgo_receiver/handlers.py`](alphaalgo_receiver/handlers.py)** and edit `on_verified_event(event)`.

Every `event` passed to `on_verified_event` has already passed raw-byte HMAC-SHA256 verification, ±300s replay checks, and SQLite `event_id` deduplication (retries will never trigger it twice):

```python
def on_verified_event(event: dict[str, Any]) -> None:
    # >>> ADD YOUR OWN READ-ONLY LOGIC HERE <<<
    inst = event["instrument"]  # single_option | vertical_credit_spread | iron_butterfly
    if event["record_kind"] != "fill" or not inst["complete"]:
        return
    for leg in inst["legs"]:
        print(event["strategy_id"], event["trade_ref"], leg["role"], leg["option_symbol"])
```

Note that top-level `event["option_symbol"]` is populated **only** for `single_option` and is `null` for multi-leg instruments (`vertical_credit_spread`, `iron_butterfly`), so iterating `event["instrument"]["legs"]` handles every strategy uniformly without naked single-leg ambiguity.

You can also compose multiple handlers programmatically with `dispatch_handlers(...)`, or enable built-in sinks via CLI:

```bash
python3 -m alphaalgo_receiver \
  --database ./receipts.db \
  --jsonl-log ./events.jsonl \
  --discord-webhook "https://discord.com/api/webhooks/..."
```

---

## Webhook Verification Spec (Schema v3)

Every delivery from the AlphaAlgo Developer Feed includes:

| Header | Description |
| :--- | :--- |
| `Webhook-Id` | Canonical `event_id` (e.g. `aa3-...`), matching `event["event_id"]` |
| `Webhook-Timestamp` | Unix epoch seconds (integer string), verified within ±300s |
| `Webhook-Key-Id` | Key identifier selecting which `whsec_...` secret to verify against |
| `Webhook-Signature` | `v1,<base64(HMAC-SHA256(secret_bytes, "{id}.{timestamp}.{raw_body}"))>` |

**Important:** Always verify against the **exact raw UTF-8 HTTP request body bytes** before parsing JSON. Do not parse and re-serialize JSON prior to signature verification.

---

## Production Hosting Notes

The AlphaAlgo Developer Feed only delivers to **public HTTPS endpoints on port 443** (no embedded credentials, query strings, or fragments).

Keep the Python receiver bound to `127.0.0.1:9091` and terminate TLS in front of it using **Caddy**, **Nginx**, or **Cloudflare Tunnel**. Example `Caddyfile`:

```caddyfile
feed.yourdomain.com {
    reverse_proxy 127.0.0.1:9091
}
```

Then register `https://feed.yourdomain.com/events` in your AlphaAlgo Developer Feed portal.

---

## Links

- **Website:** [https://alphaalgo.co](https://alphaalgo.co)
- **Subscriptions & Developer Feed Access:** [https://whop.com/alphaalgoco/](https://whop.com/alphaalgoco/)
- **Public Trade Records on X:** [@AlphaAlgoCo](https://x.com/AlphaAlgoCo)

---

## Disclaimer

AlphaAlgo provides systematic options execution telemetry strictly for informational and research purposes. AlphaAlgo is not a registered investment advisor, broker-dealer, or fiduciary, and nothing in this repository constitutes personalized financial, legal, or tax advice or a recommendation or solicitation to buy or sell any security. AlphaAlgo does not manage client funds, access brokerage accounts, guarantee delivery speed, or execute orders on behalf of subscribers; you retain sole control over your trading and risk. System Position Scale (`position_scale_x`) expresses relative source-system sizing in base units (e.g., `0.75x` or `1.00x`); it is not a fixed percentage of your account. Short-dated and 0DTE options involve substantial risk, including the potential loss of up to 100% of capital committed to a position. Past performance does not guarantee future results. Licensed under the [MIT License](LICENSE).
