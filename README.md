# AlphaAlgo Developer Feed — Signed Webhook Receiver (v3)

Official open-source reference receiver for the **[AlphaAlgo](https://alphaalgo.co)** Signed Developer Webhook Feed (`schema_version: 3`).

Built with **zero third-party dependencies** (pure Python 3.10+ standard library), this starter kit handles:

- **Raw-byte HMAC-SHA256 verification** following the [Standard Webhooks v1](https://www.standardwebhooks.com/) signing convention (`Webhook-Id`, `Webhook-Timestamp`, `Webhook-Signature`, `Webhook-Key-Id`)
- **Replay protection** (strict ±300s timestamp window)
- **Zero-downtime key rotation** (map multiple `key_id -> whsec_...` secrets simultaneously)
- **Durable SQLite (WAL) idempotency** — deduplicates retries by `event_id` and rejects mismatched payload collisions with `409 Conflict`
- **Unified Schema v3 parsing** across all 3 first-class `instrument.kind` types (`single_option`, `vertical_credit_spread`, `iron_butterfly`) with uniform `instrument.legs[]`
- **Clear extension point (`alphaalgo_receiver/handlers.py`)** — edit `on_verified_event(event)` or attach built-in JSONL / Discord / Telegram read-only sinks, optionally offloaded to a non-blocking `AsyncEventDispatcher` background queue

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

You can also compose multiple handlers programmatically with `dispatch_handlers(...)`, wrap slow sinks in `AsyncEventDispatcher(...)`, or enable built-in sinks via CLI:

```bash
python3 -m alphaalgo_receiver \
  --database ./receipts.db \
  --jsonl-log ./events.jsonl \
  --discord-webhook "https://discord.com/api/webhooks/..." \
  --telegram-bot-token "123456789:AA..." \
  --telegram-chat-id "-1001234567890" \
  --async-handlers
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

## Hosting & HTTPS Setup (Connecting to the Live Feed)

The AlphaAlgo Developer Feed delivers webhooks only to **public HTTPS URLs on port 443** with a valid CA-signed TLS certificate (no `http://`, no self-signed certs, no private/localhost IPs, and no embedded credentials, `?query`, or `#fragment`).

Always keep the Python receiver bound to `127.0.0.1:9091` and place an HTTPS reverse proxy or tunnel in front of it. Choose either **Option A** (fastest for testing, no domain required) or **Option B** (recommended for always-on hosting).

---

### Option A: Quick Testing (1 Minute, No Domain Required) — Cloudflare Quick Tunnel

Best for trying out the live read-only feed on a laptop or test VPS without buying a domain or opening firewall ports.

1. **Install `cloudflared`:**
   ```bash
   # Linux (x86_64)
   curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o ~/.local/bin/cloudflared
   chmod +x ~/.local/bin/cloudflared

   # macOS (Homebrew)
   brew install cloudflared
   ```

2. **Start a temporary HTTPS tunnel to local port `9091`:**
   ```bash
   cloudflared tunnel --url http://127.0.0.1:9091
   ```
   Copy the generated public HTTPS URL from the output, e.g. `https://example-words.trycloudflare.com`.

3. **Register the URL in Whop & copy your signing secret:**
   - Open the **AlphaAlgo Developer Feed** app inside your [Whop membership](https://whop.com/alphaalgoco/).
   - Enter `https://example-words.trycloudflare.com/events` and click **Save connection**.
   - Copy the one-time `whsec_...` signing secret shown on screen (a new connection uses key ID `v1`).

4. **Start the local receiver with that signing secret (in a second terminal):**
   ```bash
   export ALPHAALGO_RECEIVER_KEYS_JSON='{"v1":"whsec_PASTE_YOUR_SECRET_HERE"}'
   python3 -m alphaalgo_receiver \
     --database ./receipts.db \
     --jsonl-log ./events.jsonl \
     --port 9091
   ```

5. **Verify end-to-end reachability:**
   ```bash
   curl -sS https://example-words.trycloudflare.com/healthz
   # Expected: {"service": "alphaalgo-feed-receiver", "schema_version": 3, "execution": "disabled"}
   ```

> **Note:** Quick Tunnel URLs are ephemeral and change if `cloudflared` restarts (which requires updating your URL and signing secret in Whop). Use **Option B** for long-term unattended operation.

---

### Option B: Always-On Hosting (Own Domain + Automatic Free HTTPS) — Caddy + systemd

Recommended for reliable 24/7 telemetry logging on any Linux VPS (Ubuntu/Debian/etc.).

1. **Point a subdomain to your VPS:**
   - Add a DNS `A` record (for example `feed.yourdomain.com` → your VPS public IPv4).
   - Allow inbound TCP ports `80` and `443` in your firewall; keep port `9091` closed externally (loopback-only).

2. **Install Caddy and configure automatic HTTPS** (`/etc/caddy/Caddyfile`):
   ```caddyfile
   feed.yourdomain.com {
       reverse_proxy 127.0.0.1:9091
   }
   ```
   Reload Caddy (`sudo systemctl reload caddy`). Caddy automatically obtains and renews a free Let's Encrypt TLS certificate for `feed.yourdomain.com`.

3. **Register `https://feed.yourdomain.com/events` in Whop:**
   - Open the **AlphaAlgo Developer Feed** app in Whop, save `https://feed.yourdomain.com/events`, and copy the one-time `whsec_...` secret.

4. **Store your signing secret privately (`chmod 600`):**
   Create `/etc/alphaalgo-receiver.env` (never commit this file to git):
   ```bash
   ALPHAALGO_RECEIVER_KEYS_JSON={"v1":"whsec_PASTE_YOUR_SECRET_HERE"}
   ALPHAALGO_DB_PATH=/var/lib/alphaalgo-receiver/receipts.db
   ALPHAALGO_JSONL_LOG=/var/lib/alphaalgo-receiver/events.jsonl
   ALPHAALGO_HOST=127.0.0.1
   ALPHAALGO_PORT=9091
   ```
   ```bash
   sudo chmod 600 /etc/alphaalgo-receiver.env
   sudo install -d -o youruser -g youruser -m 0700 /var/lib/alphaalgo-receiver
   ```

5. **Run continuously with `systemd`** (`/etc/systemd/system/alphaalgo-receiver.service`):
   ```ini
   [Unit]
   Description=AlphaAlgo Feed v3 Signed Webhook Receiver (Read-Only Telemetry)
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=youruser
   WorkingDirectory=/opt/alphaalgo-feed-receiver
   EnvironmentFile=/etc/alphaalgo-receiver.env
   ExecStart=/usr/bin/python3 -m alphaalgo_receiver
   Restart=on-failure
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
   Enable and start it:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now alphaalgo-receiver.service
   curl -sS https://feed.yourdomain.com/healthz
   ```

### Zero-Downtime Key Rotation Tip

When you rotate or replace a connection URL in Whop, the key ID increments (`v1` → `v2`, etc.). You can keep multiple keys active simultaneously in `ALPHAALGO_RECEIVER_KEYS_JSON` so no in-flight delivery is rejected during cutover:

```json
{"v1":"whsec_OLD_SECRET","v2":"whsec_NEW_SECRET"}
```

Once verified, remove the old key from the JSON map and restart the receiver.

---

## Links

- **Website:** [https://alphaalgo.co](https://alphaalgo.co)
- **Subscriptions & Developer Feed Access:** [https://whop.com/alphaalgoco/](https://whop.com/alphaalgoco/)
- **Public Trade Records on X:** [@AlphaAlgoCo](https://x.com/AlphaAlgoCo)

---

## Disclaimer

AlphaAlgo provides systematic options execution telemetry strictly for informational and research purposes. AlphaAlgo is not a registered investment advisor, broker-dealer, or fiduciary, and nothing in this repository constitutes personalized financial, legal, or tax advice or a recommendation or solicitation to buy or sell any security. AlphaAlgo does not manage client funds, access brokerage accounts, guarantee delivery speed, or execute orders on behalf of subscribers; you retain sole control over your trading and risk. System Position Scale (`position_scale_x`) expresses relative source-system sizing in base units (e.g., `0.75x` or `1.00x`); it is not a fixed percentage of your account. Short-dated and 0DTE options involve substantial risk, including the potential loss of up to 100% of capital committed to a position. Past performance does not guarantee future results. Licensed under the [MIT License](LICENSE).
