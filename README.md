# AlphaAlgo Developer Feed — Signed Webhook Receiver (v3)

[![CI](https://github.com/AlphaAlgoCo/alphaalgo-feed-receiver/actions/workflows/ci.yml/badge.svg)](https://github.com/AlphaAlgoCo/alphaalgo-feed-receiver/actions/workflows/ci.yml)

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
  doctor.py     <-- `--doctor` config, storage & UTC clock-skew self-check
  cli.py        <-- CLI flags & wiring (`python3 -m alphaalgo_receiver`)
docs/
  SCHEMA_V3.md  <-- Full Schema v3 field contract, JSON examples & edge cases
examples/
  paper_ledger.py     <-- Read-only position state tracker (live & offline replay)
scripts/
  send_mock_event.py  <-- Send single v3 events or full lifecycle replay scenarios
tests/
  test_receiver.py        <-- Unit tests for security, HTTP bounds, SQLite, handlers
  test_paper_ledger.py    <-- Unit tests for Paper Ledger, lifecycle replay & docs
  test_doctor.py          <-- Unit tests for `--doctor` diagnostics & CI workflow
  test_deploy_configs.py  <-- Unit tests for Docker Compose HTTPS/Tunnel profiles
deploy/
  Caddyfile.docker        <-- Hardened automatic Let's Encrypt Caddy config for Compose
Dockerfile / docker-compose.yml / railway.json / render.yaml / fly.toml
AGENTS.md               <-- AI coding assistant guide (Cursor, Claude Code, Codex, etc.)
.agents/skills/         <-- Reusable Agent Skill (`alphaalgo-feed-integration/SKILL.md`)
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

# Optional: verify keys, DB writability, sinks, and UTC clock skew before starting
python3 -m alphaalgo_receiver --doctor

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

### 4. Interactive Full Lifecycle Demo (Paper Ledger + Scenario Replay)

Want to watch how a real trade flows through `entry -> entry_update -> partial_exit -> exit`, 2-leg spreads, 4-leg IBF settlement observations, exact retries (`duplicate: true`), `409 Conflict` collisions, out-of-order `trade_revision`, expired entries, incomplete instruments, and `401` tamper rejections?

Terminal 1 — start the read-only Paper Ledger receiver:

```bash
python3 examples/paper_ledger.py --serve --port 9091
```

Terminal 2 — replay the full scenario suite:

```bash
python3 scripts/send_mock_event.py --scenario full_demo --delay 0.3
```

You can also rebuild the position table offline from any existing `receipts.db` or `events.jsonl` and export it to CSV:

```bash
python3 examples/paper_ledger.py --from-db ./receipts.db --export-csv ./ledger.csv
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
  --telegram-chat-id "123456789" \
  --async-handlers
```

> **Personal Use Only — No Redistribution:** Built-in Discord and Telegram sinks are strictly for the active subscriber's own private alerting (e.g., personal DM or private server). Forwarding, broadcasting, or reselling AlphaAlgo feed data to third parties, public channels, or paid groups violates AlphaAlgo's Subscription Terms and results in immediate access termination.

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

For the complete field-by-field contract (including `record_kind`, `instrument.complete`, `trade_revision` ordering, `expires_at`, and 1-leg / 2-leg / 4-leg JSON payloads), see **[`docs/SCHEMA_V3.md`](docs/SCHEMA_V3.md)**. Using an AI coding assistant (Cursor, Claude Code, Codex, Antigravity)? Point it at **[`AGENTS.md`](AGENTS.md)** and **[`.agents/skills/alphaalgo-feed-integration/SKILL.md`](.agents/skills/alphaalgo-feed-integration/SKILL.md)**.

---

## Hosting & HTTPS Setup (Connecting to the Live Feed)

The AlphaAlgo Developer Feed delivers webhooks only to **public HTTPS URLs on port 443** with a valid CA-signed TLS certificate (no `http://`, no self-signed certs, no private/localhost IPs, and no embedded credentials, `?query`, or `#fragment`).

Always terminate TLS in front of the Python receiver. Choose **Option A** (1-minute local test), **Option B** (managed HTTPS hosting on Railway / Render / Fly.io — no VPS or domain required), or **Option C** (self-hosted VPS — one-command Docker Compose with built-in automatic Let's Encrypt HTTPS or Cloudflare Tunnel, plus manual Caddy + systemd).

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

> **Note:** Quick Tunnel URLs are ephemeral and change if `cloudflared` restarts (which requires updating your URL and signing secret in Whop). Use **Option B** or **Option C** for long-term unattended operation.

---

### Option B: Managed Always-On HTTPS (No VPS or Domain Required) — Railway / Render / Fly.io

This repository ships ready-to-use deployment configs backed by the shared [`Dockerfile`](Dockerfile), with automatic `PORT` detection and persistent `/data` storage for SQLite WAL deduplication:

- **Railway (`railway.json`)**
  1. Fork or import this repository in [Railway](https://railway.com) → **New Project → Deploy from GitHub repo** (Railway auto-detects `railway.json` + `Dockerfile`).
  2. Attach a Volume mounted at `/data` (so `receipts.db` and `events.jsonl` survive redeploys) and generate a public HTTPS domain under **Settings → Networking**.
  3. Register `https://<your-app>.up.railway.app/events` in the Whop Developer Feed portal, copy the `whsec_...` secret, and set `ALPHAALGO_RECEIVER_KEYS_JSON={"v1":"whsec_..."}` in Railway **Variables**.
- **Render (`render.yaml`)**
  1. Fork this repository, open [Render](https://render.com) → **New → Blueprint**, and select your fork. `render.yaml` provisions the Docker web service, `/healthz` check, and 1 GB `/data` persistent disk automatically.
  2. Register `https://<your-service>.onrender.com/events` in Whop, copy your `whsec_...` secret, and set `ALPHAALGO_RECEIVER_KEYS_JSON` in Render **Environment** (plus optional `DISCORD_WEBHOOK_URL` or `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`).
- **Fly.io (`fly.toml`)**
  1. Edit `app = "..."` in [`fly.toml`](fly.toml) to a globally unique name (or run `fly launch --no-deploy`).
  2. Create a persistent volume and deploy:
     ```bash
     fly volumes create alphaalgo_data --region ewr --size 1
     fly secrets set ALPHAALGO_RECEIVER_KEYS_JSON='{"v1":"whsec_PASTE_YOUR_SECRET_HERE"}'
     fly deploy
     ```
  3. Register `https://<your-app>.fly.dev/events` in Whop and verify `curl -sS https://<your-app>.fly.dev/healthz`.

---

### Option C: Self-Hosted VPS — One-Command Docker Compose with Built-in HTTPS (Recommended)

[`docker-compose.yml`](docker-compose.yml) includes optional sidecar profiles so you do **not** have to install Python, Caddy, Certbot, or `systemd` on your VPS. Pick the profile that matches your setup:

#### C1. Own Domain + Automatic Free Let's Encrypt HTTPS (`--profile https`)

Best for 24/7 self-hosted telemetry on any Linux VPS (requires a subdomain whose DNS `A` record points to your VPS IP and open inbound TCP ports `80` and `443`; port `9091` stays loopback-only).

1. **Register `https://feed.yourdomain.com/events` in Whop** (inside the AlphaAlgo Developer Feed app) and copy your one-time `whsec_...` signing secret.
2. **Configure `.env`** (`chmod 600 .env`, never commit):
   ```bash
   cp .env.example .env
   chmod 600 .env
   ```
   Edit `.env` and set:
   ```bash
   ALPHAALGO_DOMAIN=feed.yourdomain.com
   ALPHAALGO_RECEIVER_KEYS_JSON={"v1":"whsec_PASTE_YOUR_SECRET_HERE"}
   ```
3. **Start both the receiver and automatic HTTPS proxy with one command:**
   ```bash
   docker compose --profile https up -d --build
   ```
   The bundled `caddy:2-alpine` sidecar ([`deploy/Caddyfile.docker`](deploy/Caddyfile.docker)) automatically obtains and renews a free Let's Encrypt certificate (persisted in the `caddy_data` volume), enforces HSTS and a 64 KB body limit, strips the `Server` header, and forwards requests over the private Docker network to `alphaalgo-receiver:9091`.
4. **Verify:**
   ```bash
   curl -sS https://feed.yourdomain.com/healthz
   # Expected: {"service": "alphaalgo-feed-receiver", "schema_version": 3, "execution": "disabled"}
   ```

#### C2. No Domain / No Open Firewall Ports (`--profile tunnel` or `--profile named-tunnel`)

> Use modern Docker Compose v2 (`docker compose` with a space, not legacy `docker-compose`).

- **Instant temporary HTTPS (zero domain, zero account, testing only):**
  1. Start with a temporary placeholder signing key so `alphaalgo-receiver` becomes healthy and `cloudflared-quick` prints your public URL:
     ```bash
     cp .env.example .env && chmod 600 .env
     # Replace the placeholder key in .env with any valid dummy whsec_ key first:
     python3 -c 'from alphaalgo_receiver import generate_signing_secret; print(f"ALPHAALGO_RECEIVER_KEYS_JSON={{\"v1\":\"{generate_signing_secret()}\"}}")'
     docker compose --profile tunnel up -d --build
     docker compose --profile tunnel logs -f cloudflared-quick
     ```
  2. Copy the printed `https://<random>.trycloudflare.com` URL (press `Ctrl+C` to exit logs — containers stay running), register `https://<random>.trycloudflare.com/events` in Whop, and paste the real one-time `whsec_...` secret into `.env`.
  3. **Reload only `alphaalgo-receiver` without restarting `cloudflared-quick`** so the public tunnel URL does **not** change:
     ```bash
     docker compose --profile tunnel up -d --no-deps --force-recreate alphaalgo-receiver
     curl -sS https://<random>.trycloudflare.com/healthz
     ```
- **Permanent fixed HTTPS without opening ports 80/443 (Cloudflare Zero Trust Named Tunnel):**
  1. In Cloudflare Zero Trust → **Networks → Tunnels**, create a free tunnel routing your hostname (e.g. `feed.yourdomain.com`) to `http://alphaalgo-receiver:9091`, and copy the Tunnel Token.
  2. Set `CLOUDFLARE_TUNNEL_TOKEN=...` and `ALPHAALGO_RECEIVER_KEYS_JSON=...` in `.env`, then run:
     ```bash
     docker compose --profile named-tunnel up -d --build
     ```

#### C3. Bring Your Own Reverse Proxy (Default Profile)

If your VPS already runs Nginx, Caddy, or Traefik on ports `80`/`443`, run the default Compose profile without any HTTPS sidecar — it binds strictly to `127.0.0.1:9091` and will not touch ports `80`/`443`:

```bash
cp .env.example .env && chmod 600 .env
docker compose up -d --build
curl -sS http://127.0.0.1:9091/healthz
```

#### C4. Bare-Metal Linux VPS (No Docker) — Host Caddy + systemd

Prefer running Python directly on Ubuntu/Debian without Docker?

1. Point a subdomain DNS `A` record (`feed.yourdomain.com` → VPS IPv4), open inbound TCP `80`/`443`, and keep `9091` closed externally.
2. Install Caddy, configure `/etc/caddy/Caddyfile`, and reload (`sudo systemctl reload caddy`):
   ```caddyfile
   feed.yourdomain.com {
       reverse_proxy 127.0.0.1:9091
   }
   ```
3. Register `https://feed.yourdomain.com/events` in Whop and save the one-time `whsec_...` secret in `/etc/alphaalgo-receiver.env` (`chmod 600`):
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
4. Create `/etc/systemd/system/alphaalgo-receiver.service`:
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
   Enable and verify:
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
