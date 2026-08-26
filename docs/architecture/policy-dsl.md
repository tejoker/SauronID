# Policy DSL — Sprint 1 Reference

Declarative YAML/JSON spec describing what an agent may do. Parser ships in
`core::policy` (`parse`, `parse_yaml`, `parse_json`). Schema for IDE
autocomplete: `schemas/policy.schema.json`.

## Top-level fields

| Field         | Type             | Required | Notes |
|---------------|------------------|----------|-------|
| `version`     | string           | yes      | Must be `"1"`. Anything else → `UnsupportedVersion`. |
| `agent`       | string           | yes      | Non-empty agent id or label. |
| `description` | string           | no       | Free-form. |
| `binding`     | object           | no       | See below. Absent => empty binding. |
| `invariants`  | list of strings  | no       | Predicate strings. Parsed in Sprint 2 by the policy compiler. |
| `metadata`    | object           | no       | Free-form; unknown keys allowed. |

Unknown top-level fields → parser error (`deny_unknown_fields`).

## `binding`

| Field                   | Type        | Required | Semantics |
|-------------------------|-------------|----------|-----------|
| `allowed_tools`         | list[str]   | no       | Tool ids the agent may call. Absent => any tool permitted by upstream. |
| `max_budget_usd`        | number ≥ 0  | no       | Finite, non-negative spend cap for the policy lifetime. |
| `data_scope`            | object      | no       | `allow` + `deny` classification tag lists. Sets must be disjoint. |
| `rate_limit`            | object      | no       | `{ requests_per_minute: u32 > 0 }`. |
| `time_window`           | object      | no       | `{ start: "HH:MM", end: "HH:MM", timezone: IANA }`. Leading zeros required (`09:00`, not `9:00`). |
| `required_signatures`   | list[obj]   | no       | Each entry `{ role: str, threshold: u32 > 0 }`. M-of-N gating; enforced in Sprint 2. |
| `delegation`            | object      | no       | `{ max_depth: u32, allowed_subagents: [str] }`. `max_depth: 0` disables delegation. |

### `data_scope`

```yaml
data_scope:
  allow: [public, customer_owned]
  deny:  [pii, financial_records]
```

Canonical tags: `public`, `customer_owned`, `pii`, `financial` (alias
`financial_records`), `restricted`. Unknown tags fall through as
`DataClassification::Custom(...)` at the type layer. `allow` and `deny`
must be disjoint or the parser rejects.

### `time_window`

`HH:MM` 24-hour. `timezone` must resolve via `chrono_tz` (IANA).
`Europe/Wakanda` is not a tz; the parser will say so.

### `required_signatures`

M-of-N gating per role. The runtime evaluator in Sprint 2 counts
distinct signatures per role.

## `invariants`

Free-form strings now. Examples:

```yaml
invariants:
  - "spend_total <= max_budget_usd"
  - "data_classification != 'restricted'"
  - "no_external_call_to(domain: 'competitor.com')"
```

Invariant predicate syntax is parsed by the policy compiler. The grammar and
the supported operators live in `core/src/policy/invariants/`.

## `metadata`

Freely extensible — `additionalProperties: true`. Recommended keys:
`created_at`, `author`, `tags`.

## Worked examples

### Banking payment agent

```yaml
version: "1"
agent: payment_agent_eu
description: SEPA payments with hard cap and EU hours.
binding:
  allowed_tools: [sepa_payment_initiate, ledger_read, fx_quote]
  max_budget_usd: 5000
  data_scope:
    allow: [customer_owned, financial]
    deny:  [pii, restricted]
  rate_limit: { requests_per_minute: 30 }
  time_window: { start: "09:00", end: "18:00", timezone: "Europe/Paris" }
  required_signatures:
    - { role: human_approver, threshold: 1 }
invariants:
  - "spend_total <= max_budget_usd"
  - "payment_currency in ('EUR', 'USD')"
```

### Healthcare records assistant (2-of-3 clinician sigs)

```yaml
version: "1"
agent: healthcare_records_assistant
binding:
  allowed_tools: [ehr_query, de_identify, aggregate_stats]
  data_scope:
    allow: [customer_owned]
    deny:  [pii, restricted, financial]
  required_signatures:
    - { role: clinician, threshold: 2 }
invariants:
  - "data_classification != 'restricted'"
  - "no_raw_pii_in_output"
```

### Minimal viable policy

```yaml
version: "1"
agent: minimal_agent
invariants:
  - "spend_total <= 1"
```

## Authoring tips

- **VSCode autocomplete.** Install the *YAML* extension. Top of each
  file:
  ```yaml
  # yaml-language-server: $schema=../policy.schema.json
  ```
  Path relative to the YAML file. Schema file lives at
  `schemas/policy.schema.json`.

- **Local validation.** Run the CLI:
  ```
  cargo run --bin sauronid-cli -- policy validate path/to/policy.yaml
  ```
  Prints `OK` on success or the schema/parse error.

- **JSON too.** Same parser handles JSON. Auto-detection: first
  non-whitespace char `{` → JSON, else YAML.

- **Round-trip safe.** Parse → `serde_yml::to_string` → re-parse yields
  the same AST. Covered by tests.

## Error taxonomy

| Variant                       | Trigger |
|-------------------------------|---------|
| `InvalidYaml(msg)`            | YAML lexer/parser failure or unknown top-level field. |
| `InvalidJson(msg)`            | JSON lexer/parser failure or unknown top-level field. |
| `SchemaViolation(msg)`        | Structurally valid but semantically rejected (bad tz, negative budget, allow/deny overlap, zero rate, zero threshold). |
| `UnsupportedVersion(msg)`     | `version` not `"1"`. |

## Forward compatibility

Sprint 2 will:
- compile `invariants` strings into an AST + runtime evaluator;
- promote `Budget` and `Allowlist` newtypes into the runtime layer;
- wire the policy into the agent action pipeline.
