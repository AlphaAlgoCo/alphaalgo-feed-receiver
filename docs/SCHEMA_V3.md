# AlphaAlgo Developer Feed — Schema v3 Contract & Edge-Case Reference

This document is the authoritative wire-format specification for the **AlphaAlgo Signed Developer Webhook Feed (`schema_version: 3`)**. It is designed for both human engineers and AI coding assistants building downstream consumers.

> **Read-Only Telemetry Notice:** AlphaAlgo webhooks publish factual, post-fill execution telemetry for research, monitoring, and software integration. AlphaAlgo never manages funds, accesses subscriber brokerage accounts, or places orders on behalf of subscribers.

---

## 1. HTTP Transport & Signature Verification

Every webhook delivery is an HTTP `POST` with `Content-Type: application/json` to your registered public HTTPS endpoint (`/events` by default in this receiver).

### Required Headers (Standard Webhooks v1)

| Header | Format | Verification Rule |
| :--- | :--- | :--- |
| `Webhook-Id` | Canonical `event_id` (e.g., `aa3-<64-hex>`) | Must match `event["event_id"]` in JSON body |
| `Webhook-Timestamp` | Unix epoch seconds (ASCII integer string) | Must be within `±300` seconds of receiver UTC clock |
| `Webhook-Key-Id` | Optional rotation label (e.g., `v1`, `v2`) | Informational metadata; receivers verifying directly with `ALPHAALGO_SIGNING_SECRET` do not need to match key IDs |
| `Webhook-Signature` | Space-separated list of `v1,<base64>` signatures | Constant-time HMAC-SHA256 match against exact raw body bytes |

### Signature Computation

```text
secret_bytes   = base64_decode(secret.removeprefix("whsec_"))  # >= 32 bytes
signed_payload = f"{Webhook-Id}.{Webhook-Timestamp}.".encode("ascii") + raw_http_body_bytes
expected_sig   = "v1," + base64_encode(HMAC_SHA256(secret_bytes, signed_payload))
```

**Critical:** Always verify the signature against the **exact raw UTF-8 HTTP request bytes** before parsing JSON. Never parse and re-serialize JSON before verification.

### Expected Receiver HTTP Status Codes

| Status | Meaning |
| :--- | :--- |
| `200 OK` | Verified and durably persisted (`duplicate: false`), OR exact retry of an already-persisted `event_id` (`duplicate: true`) |
| `400 Bad Request` | Malformed HTTP framing, wrong `Content-Type`, body > 64 KiB, non-standard JSON (`NaN`/`Infinity`), `schema_version != 3`, or `Webhook-Id != body.event_id` |
| `401 Unauthorized` | Missing/malformed headers, stale timestamp (`> ±300s`), or invalid HMAC signature (or unknown `Webhook-Key-Id` when using legacy key-ID mapping) |
| `409 Conflict` | Same `event_id` received again with a **different** raw payload SHA-256 hash |
| `503 Service Unavailable` | Transient receiver storage/internal error (signals upstream retry) |

---

## 2. Top-Level Event Envelope (`schema_version: 3`)

All numeric prices/quantities are standard JSON numbers (`NaN` and `Infinity` are never valid).

### Identity & Ordering

| Field | Type | Description |
| :--- | :--- | :--- |
| `schema_version` | `int` | Always `3` (strict integer; reject `2` or `3.0`) |
| `event_id` | `str` | Globally unique canonical event ID (`aa3-<sha256>`). Use as idempotency key. |
| `source_event_id` | `str` | Source-local event identifier before canonical hashing |
| `source_id` | `str` | Logical producer identifier (e.g., `"phase1"`, `"mock"`) |
| `trade_ref` | `str` | Atomic trade identifier linking `entry -> entry_update -> partial_exit -> exit` |
| `trade_revision` | `int` | Strictly monotonic revision integer per `trade_ref`. **Ignore events with `trade_revision <= last_applied_revision` to guard against out-of-order delivery.** |
| `event_kind` | `str` | One of `"entry"`, `"entry_update"`, `"partial_exit"`, `"exit"`, `"snapshot"` |

### Record Classification & Execution Origin

| Field | Type | Description |
| :--- | :--- | :--- |
| `record_kind` | `str` | `"fill"` (broker-confirmed live execution), `"settlement_observation"` (expiry cash-settlement observation), or `"non_execution_close"` (non-fill close observation) |
| `broker_execution` | `bool \| null` | `false` for non-execution observations (`record_kind != "fill"`); `null` on normal broker fills |
| `settlement_model` | `str \| null` | Present on `settlement_observation` (e.g., `"spxw_european_cash_settlement_1600"`, `"modelled_0dte_otm_expiry_zero"`, `"broker_confirmed_spxw_pm_cash_settlement"`) |
| `settlement_underlying_price` | `float \| null` | Underlying settlement print used for `settlement_observation`, else `null` |
| `source_execution` | `object` | Public origin summary: `{live_origin_verified, broker, environment, evidence_source}`. Never contains account IDs or broker order IDs. |

### Strategy & Contract Fields

| Field | Type | Description |
| :--- | :--- | :--- |
| `strategy_id` | `str` | Canonical strategy identifier (e.g., `"S608"`, `"S623"`, `"S650"`, `"S651"`, `"S660"`, `"S661"`, `"S662"`) |
| `sub_strategy` | `str \| null` | Strategy structure tag when applicable: `"CCS"`, `"CPS"`, `"IBF"`, or `null` |
| `ticker` | `str` | Underlying symbol (e.g., `"SPX"`, `"SPY"`, `"NVDA"`) |
| `option_symbol` | `str \| null` | OCC option symbol **only when `instrument.kind == "single_option"`**. Explicitly `null` for multi-leg instruments (`vertical_credit_spread`, `iron_butterfly`) so consumers never misread one leg as a standalone contract. |
| `instrument` | `object` | Structured Descriptor v1 (see Section 3). **Always inspect `instrument.legs[]`.** |

### Quantities, Relative Scale & Prices

| Field | Type | Description |
| :--- | :--- | :--- |
| `position_scale_x` | `float \| null` | Relative source-system scale in customer-defined base units (e.g., `0.75`, `1.0`). **Not** an account percentage. |
| `position_scale_max_x` | `float \| null` | Upper bound for `position_scale_x` within the strategy entry scope |
| `position_scale_basis` | `str` | `"system_base_unit_customer_defined"` |
| `position_scale_max_scope` | `str` | `"strategy_entry"` |
| `reference_allocation_x` | `float \| null` | Alias matching `position_scale_x` |
| `allocation_basis` | `str` | `"system_base_unit_customer_defined"` |
| `entry_quantity` | `int` | Total source contracts (1-leg) or spreads (multi-leg) opened for this `trade_ref` |
| `exit_fill_quantity` | `int` | Quantity closed in **this** event (`0` on `entry`/`entry_update`) |
| `cumulative_exit_quantity` | `int` | Total quantity closed across all exits for this `trade_ref` |
| `remaining_quantity` | `int` | Open quantity remaining. **Invariant:** `remaining_quantity + cumulative_exit_quantity == entry_quantity` |
| `entry_price` | `float \| null` | Entry fill price per share (debit for long single options; positive net credit per share for credit spreads & IBFs) |
| `entry_cost` | `float \| null` | Source notional/cost snapshot when available |
| `exit_fill_price` | `float \| null` | Exit fill price per share on `partial_exit`/`exit` (positive net debit per share for credit spreads & IBFs); `null` on `entry`/`entry_update` |
| `cumulative_pnl_dollars` | `float \| null` | Cumulative source-system realized PnL in dollars |
| `cumulative_return_pct` | `float \| null` | Cumulative return percentage (`return_basis` defined on `instrument` for spreads/IBFs) |

### Timestamps, Freshness & Reconciliation

| Field | Type | Description |
| :--- | :--- | :--- |
| `fill_timestamp` | `float \| null` | Broker-reported Unix epoch seconds when `fill_time_verified` is `true`; otherwise `null` |
| `observed_timestamp` | `float \| null` | Known observation/fill Unix epoch seconds (`null` when `fill_time_unknown` is `true`) |
| `fill_time_verified` | `bool` | `true` only when `record_kind == "fill"` and `fill_time_provenance == "broker_reported"` |
| `broker_fill_time_unknown` | `bool` | Logical inverse of `fill_time_verified` |
| `fill_time_provenance` | `str` | e.g., `"broker_reported"`, `"producer_reported"`, `"system_observed_terminal_fill"`, `"settlement_model_observation"`, `"non_execution_close_observation"`, `"unverified"` |
| `fill_time_unknown` | `bool` | `true` if no trustworthy observation timestamp is known |
| `published_at` | `float` | Unix epoch seconds when the feed publisher emitted this envelope |
| `expires_at` | `float \| null` | Soft freshness deadline for `entry` / `entry_update` events (`observed_timestamp + entry_ttl`, typically 30s). `null` on exits. |
| `expiry_reason` | `str \| null` | `null`, `"stale_entry"`, or `"unknown_fill_time"` |
| `requires_position_reconciliation` | `bool` | `true` on `entry_update`, `partial_exit`, and `exit`; signals consumers to reconcile local state for `trade_ref` |
| `disclaimer` | `str` | Standard informational telemetry disclaimer |

---

## 3. Instrument Descriptor v1 (`event["instrument"]`)

Every event includes `instrument` with `descriptor_version: 1`, `kind`, `complete`, `incomplete_reason`, `quantity_unit`, `contract_multiplier`, and `legs[]`.

### Supported `instrument.kind` Types

| `instrument.kind` | `structure` | `quantity_unit` | Legs (`role`) | Entry / Exit Price Basis |
| :--- | :--- | :--- | :--- | :--- |
| `single_option` | *(omitted)* | `"contracts"` | 1 leg: `single` | Long debit entry / sell-to-close credit |
| `vertical_credit_spread` | `"CCS"` or `"CPS"` | `"spreads"` | 2 legs: `short`, `long` | `entry_price`: positive net credit/share; `exit_fill_price`: positive net debit/share |
| `iron_butterfly` | `"IBF"` | `"spreads"` | 4 legs: `short_call`, `long_call`, `short_put`, `long_put` | `entry_price`: positive net credit/share; `exit_fill_price`: positive net debit/share; includes `center_strike` & `spread_width_points` |

### Uniform Leg Object (`instrument["legs"][i]`)

Each leg carries:
- `role`: `"single"` | `"short"` | `"long"` | `"short_call"` | `"long_call"` | `"short_put"` | `"long_put"`
- `option_symbol`: OCC 21-character symbol (e.g., `"SPXW261123P06000000"`)
- `root`: Option root (e.g., `"NVDA"`, `"SPY"`, `"SPXW"`)
- `expiration`: ISO date `"YYYY-MM-DD"`
- `right`: `"C"` or `"P"`
- `strike`: Numeric strike price (float)
- `ratio`: Integer ratio (`1` when `complete: true`)
- `entry_side`: `"buy_to_open"` or `"sell_to_open"` (present when `complete: true`)
- `exit_side`: `"sell_to_close"` or `"buy_to_close"` (present when `complete: true`)

### Incomplete Instrument Handling (`complete: false`)

If source metadata fails any structural invariant, the publisher sets `instrument["complete"] = false`, `contract_multiplier = null`, omits leg ratios/sides, and populates `incomplete_reason` with a fixed code such as:
- `invalid_option_symbol`
- `missing_or_invalid_spread_leg`
- `missing_or_invalid_spread_type`
- `conflicting_spread_metadata` / `conflicting_spread_type`
- `spread_legs_mismatch` / `spread_right_mismatch` / `spread_strike_direction_invalid` / `spread_width_mismatch`
- `unsupported_spread_ratio` / `unsupported_spread_contract_multiplier`
- `legacy_short_symbol_mismatch` / `invalid_net_entry_credit`

**Fail-Closed Rule:** Consumers must NEVER treat an incomplete multi-leg descriptor (`complete: false`) as a single-leg option. Log it for audit and skip downstream actions that require complete legs.

---

## 4. Wire Format Examples

### 4.1 Single-Leg Equity Option (`single_option`)

```json
{
  "schema_version": 3,
  "event_id": "aa3-example-single-option-001",
  "trade_ref": "DEMO-EQ-001",
  "trade_revision": 1,
  "event_kind": "entry",
  "record_kind": "fill",
  "strategy_id": "S608",
  "sub_strategy": null,
  "ticker": "NVDA",
  "option_symbol": "NVDA261218C00150000",
  "position_scale_x": 0.75,
  "entry_quantity": 4,
  "exit_fill_quantity": 0,
  "cumulative_exit_quantity": 0,
  "remaining_quantity": 4,
  "entry_price": 4.25,
  "exit_fill_price": null,
  "fill_time_verified": true,
  "requires_position_reconciliation": false,
  "instrument": {
    "descriptor_version": 1,
    "kind": "single_option",
    "complete": true,
    "incomplete_reason": null,
    "quantity_unit": "contracts",
    "contract_multiplier": 100,
    "legs": [
      {
        "role": "single",
        "option_symbol": "NVDA261218C00150000",
        "root": "NVDA",
        "expiration": "2026-12-18",
        "right": "C",
        "strike": 150.0,
        "ratio": 1,
        "entry_side": "buy_to_open",
        "exit_side": "sell_to_close"
      }
    ]
  }
}
```

### 4.2 Two-Leg Vertical Credit Spread (`vertical_credit_spread`)

```json
{
  "schema_version": 3,
  "event_id": "aa3-example-spx-spread-001",
  "trade_ref": "DEMO-SPX-001",
  "trade_revision": 1,
  "event_kind": "entry",
  "record_kind": "fill",
  "strategy_id": "S623",
  "sub_strategy": "CPS",
  "ticker": "SPX",
  "option_symbol": null,
  "position_scale_x": 1.0,
  "entry_quantity": 1,
  "exit_fill_quantity": 0,
  "cumulative_exit_quantity": 0,
  "remaining_quantity": 1,
  "entry_price": 2.4,
  "exit_fill_price": null,
  "fill_time_verified": true,
  "requires_position_reconciliation": false,
  "instrument": {
    "descriptor_version": 1,
    "kind": "vertical_credit_spread",
    "structure": "CPS",
    "complete": true,
    "incomplete_reason": null,
    "quantity_unit": "spreads",
    "spread_width_points": 20.0,
    "contract_multiplier": 100,
    "entry_price_basis": "positive_net_credit_per_share",
    "exit_price_basis": "positive_net_debit_per_share",
    "return_basis": "original_entry_net_credit",
    "legs": [
      {
        "role": "short",
        "option_symbol": "SPXW261123P06000000",
        "root": "SPXW",
        "expiration": "2026-11-23",
        "right": "P",
        "strike": 6000.0,
        "ratio": 1,
        "entry_side": "sell_to_open",
        "exit_side": "buy_to_close"
      },
      {
        "role": "long",
        "option_symbol": "SPXW261123P05980000",
        "root": "SPXW",
        "expiration": "2026-11-23",
        "right": "P",
        "strike": 5980.0,
        "ratio": 1,
        "entry_side": "buy_to_open",
        "exit_side": "sell_to_close"
      }
    ]
  }
}
```

### 4.3 Four-Leg Iron Butterfly (`iron_butterfly`)

```json
{
  "schema_version": 3,
  "event_id": "aa3-example-spx-ibf-001",
  "trade_ref": "DEMO-IBF-001",
  "trade_revision": 1,
  "event_kind": "entry",
  "record_kind": "fill",
  "strategy_id": "S662",
  "sub_strategy": "IBF",
  "ticker": "SPX",
  "option_symbol": null,
  "position_scale_x": 1.0,
  "entry_quantity": 1,
  "exit_fill_quantity": 0,
  "cumulative_exit_quantity": 0,
  "remaining_quantity": 1,
  "entry_price": 11.2,
  "exit_fill_price": null,
  "fill_time_verified": true,
  "requires_position_reconciliation": false,
  "instrument": {
    "descriptor_version": 1,
    "kind": "iron_butterfly",
    "structure": "IBF",
    "complete": true,
    "incomplete_reason": null,
    "quantity_unit": "spreads",
    "center_strike": 6000.0,
    "spread_width_points": 15.0,
    "contract_multiplier": 100,
    "entry_price_basis": "positive_net_credit_per_share",
    "exit_price_basis": "positive_net_debit_per_share",
    "return_basis": "original_entry_net_credit",
    "legs": [
      {
        "role": "short_call",
        "option_symbol": "SPXW261123C06000000",
        "root": "SPXW",
        "expiration": "2026-11-23",
        "right": "C",
        "strike": 6000.0,
        "ratio": 1,
        "entry_side": "sell_to_open",
        "exit_side": "buy_to_close"
      },
      {
        "role": "long_call",
        "option_symbol": "SPXW261123C06015000",
        "root": "SPXW",
        "expiration": "2026-11-23",
        "right": "C",
        "strike": 6015.0,
        "ratio": 1,
        "entry_side": "buy_to_open",
        "exit_side": "sell_to_close"
      },
      {
        "role": "short_put",
        "option_symbol": "SPXW261123P06000000",
        "root": "SPXW",
        "expiration": "2026-11-23",
        "right": "P",
        "strike": 6000.0,
        "ratio": 1,
        "entry_side": "sell_to_open",
        "exit_side": "buy_to_close"
      },
      {
        "role": "long_put",
        "option_symbol": "SPXW261123P05985000",
        "root": "SPXW",
        "expiration": "2026-11-23",
        "right": "P",
        "strike": 5985.0,
        "ratio": 1,
        "entry_side": "buy_to_open",
        "exit_side": "sell_to_close"
      }
    ]
  }
}
```

---

## 5. Consumer Safety Checklist (8 Invariants)

1. **Verify raw bytes first**: Never decode or re-encode JSON before HMAC-SHA256 verification.
2. **Persist idempotency before side effects**: Deduplicate by `event_id` in durable storage (SQLite WAL) and return `200` on exact retries, `409` on hash mismatch.
3. **Enforce monotonic `trade_revision`**: Key local state by `trade_ref` and ignore late-arriving events where `trade_revision <= last_applied_revision`.
4. **Always read `instrument["legs"]`**: Never assume `event["option_symbol"]` is non-null; it is intentionally `null` for spreads and iron butterflies.
5. **Check `record_kind` and `instrument["complete"]`**: Distinguish `"fill"` from `"settlement_observation"` / `"non_execution_close"`, and fail closed when `complete` is `false`.
6. **Respect `expires_at` on entries**: Entry telemetry includes a soft freshness deadline (`expires_at`). Inspect `expiry_reason` and compare `now > expires_at` before acting on latency-sensitive alerts.
7. **Honor `requires_position_reconciliation`**: Expect `true` on `entry_update`, `partial_exit`, and `exit`; reconcile remaining quantities (`remaining_quantity + cumulative_exit_quantity == entry_quantity`).
8. **Return HTTP `200 OK` fast**: Use `AsyncEventDispatcher` (`--async-handlers`) or a queue whenever downstream handlers perform network or database I/O.
