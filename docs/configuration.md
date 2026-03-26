# Configuration Reference

OAG policies are human-readable and deterministic. The policy model defaults to deny and explicitly allows known-safe destinations, methods, and paths.

## Policy Model

- Default action: deny.
- Rules are evaluated in a deterministic order.
- Deny rules have priority over allow rules when both match.
- Redirect targets are evaluated as new requests when `--enforce-redirect-policy` is enabled. [RFC9110] [RFC7231]
- If `enforce_dns_resolution` is enabled, hostnames must resolve to at least one IP before policy evaluation for HTTP requests.

## Example Policy

```yaml
version: 1

defaults:
  action: deny
  max_body_bytes: 1048576
  enforce_dns_resolution: false

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]
    tags: [ai, billing]

  - id: github_readonly
    host: "*.github.com"
    methods: [GET]
    paths: [/*]
    header_match:
      - header: Authorization
        present: true
      - header: X-Source
        value: agent
    header_rewrites:
      - action: SET
        header: X-Source
        value: oag-proxy
      - action: REMOVE
        header: X-Internal-Debug

deny:
  - id: cloud_metadata
    host: 169.254.169.254
    error_response:
      status: 451
      body: '{"error":"access_denied","message":"Cloud metadata access blocked"}'
      content_type: application/json

  - id: local_ip_ranges
    host: 10.0.0.1
    ip_ranges: ["10.0.0.0/24", "fd00::/8"]

secret_scopes:
  - id: OPENAI_KEY
    hosts: [api.openai.com]
    methods: [POST]
    paths: [/v1/*]
    ip_ranges: ["203.0.113.0/24"]
```

## Rule Fields

- `id`: Stable identifier used in audit logs. Must not contain whitespace.
- `host`: Exact match or wildcard (`*.example.com`). Must not start with `.`, must not contain consecutive dots, and must not include a port.
- `methods`: Allowed HTTP methods.
- `paths`: Prefix or glob match. Paths must start with `/` or `*`, must not contain whitespace, and must not include scheme/host.
- `secrets`: Secret IDs allowed to materialize for this destination.
- Secret IDs must not contain whitespace.
- `ip_ranges`: Optional CIDR ranges (IPv4/IPv6). Only matches when the request host is an IP literal within any listed range.
- `reason_code`: Optional custom reason code string. When a rule matches, this value is emitted in audit logs instead of the built-in `allowed_by_rule` or `denied_by_rule`. Must not contain whitespace.
- `rate_limit`: Optional rate limiting for matched requests.
  - `requests_per_second`: Token refill rate (required).
  - `burst`: Maximum burst size (tokens available immediately, required).
  Both `requests_per_second` and `burst` must be specified together.
  When a request matches a rate-limited rule but the token bucket is exhausted, the request is denied with reason code `rate_limited`.
- `max_body_bytes`: Optional override of the global limit for this rule.
- `connect_timeout_ms`: Optional per-rule override for the upstream connect timeout (milliseconds). Falls back to the global `--connect-timeout-ms` value when not set. Must be greater than 0.
- `read_timeout_ms`: Optional per-rule override for the upstream read timeout (milliseconds). Falls back to the global `--read-timeout-ms` value when not set. Must be greater than 0.
- `body_match`: Optional content matching constraints for request bodies.
  - `contains`: List of literal strings that must all appear in the body.
  - `patterns`: List of regex patterns that must all match in the body.
  Both `contains` and `patterns` use AND semantics: all entries must match.
- `response_body_match`: Optional content matching constraints for upstream response bodies.
  - `contains`: List of literal strings that must all appear in the response body.
  - `patterns`: List of regex patterns that must all match in the response body.
  When a response matches, the audit event records `response_injection_detected`. Only applies to fixed-length responses within `max_response_scan_bytes`.
- `skip_response_scanning`: When `true`, disables response body scanning for this rule even if `response_body_match` is defined. Useful for temporarily disabling scanning without removing configuration.
- `content_inspection`: Per-rule content inspection override. When set, overrides the defaults-level `content_inspection` for requests matching this rule.
  - `enable_builtin_patterns`: Enable built-in injection pattern library.
  - `custom_patterns`: List of regex patterns (anchor: `any`).
  - `anchored_patterns`: List of patterns with explicit anchor modes. See below.
- `skip_content_inspection`: When `true`, disables content inspection for this rule even if defaults-level content inspection is enabled.
  Cannot be combined with per-rule `content_inspection`.
  Per-rule `content_inspection` also supports `scan_streaming_responses` to override the defaults-level streaming scan setting for that rule.
- `header_rewrites`: Optional list of header rewrite operations applied to the upstream request before forwarding. Each entry specifies:
  - `action`: One of `SET`, `REMOVE`, or `APPEND`.
    - `SET`: Overwrites or creates the header with the given value.
    - `REMOVE`: Strips the header from the upstream request. No audit entry is emitted if the header was already absent.
    - `APPEND`: Appends the value to an existing header (comma-separated), or creates it if absent.
  - `header`: The header name. Must not be blank, must not contain whitespace, and must not be a reserved header (`Host`, `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Connection`, `Proxy-Connection`).
  - `value`: The header value (required for `SET` and `APPEND`, ignored for `REMOVE`).
  Rewrites are applied after secret materialization. Audit events include a `header_rewrites` array recording each rewrite that was applied.
- `query_match`: Optional list of URL query parameter constraints. All entries must match (AND semantics). Each entry specifies:
  - `param`: Query parameter name (case-sensitive).
  - `value`: Exact value match (case-insensitive). Mutually exclusive with `pattern` and `present`.
  - `pattern`: Regex pattern to match against the parameter value. Mutually exclusive with `value` and `present`.
  - `present`: Boolean. When `true`, the parameter must exist. When `false`, the parameter must be absent. Mutually exclusive with `value` and `pattern`.
- `header_match`: Optional list of request header constraints. All entries must match (AND semantics). Each entry specifies:
  - `header`: Header name (case-insensitive matching).
  - `value`: Exact value match (case-insensitive). Mutually exclusive with `pattern` and `present`.
  - `pattern`: Regex pattern to match against the header value. Mutually exclusive with `value` and `present`.
  - `present`: Boolean. When `true`, the header must exist. When `false`, the header must be absent. Mutually exclusive with `value` and `pattern`.
- `tags`: Optional list of string labels for categorizing matched requests. Tags are emitted in audit events and Prometheus metrics. Must not contain whitespace.
- `error_response`: Optional custom error response for denied requests matching this rule.
  - `status`: HTTP status code (400-599). Defaults to 403 when omitted.
  - `body`: Response body string (max 8192 characters).
  - `content_type`: Content-Type header value. Defaults to `text/plain` when omitted.
  When a deny rule with `error_response` matches, the proxy returns the custom status code and body instead of the default `403 Forbidden` with no body.
- `tls_inspect`: When `true`, enables TLS interception for CONNECT tunnels matching this rule. Requires `--tls-inspect` at runtime. Decrypted traffic passes through the full body inspection pipeline. See [security.md](security.md#tls-interception).
- `skip_outbound_credential_detection`: When `true`, disables outbound credential detection for this rule even if enabled at defaults level.
- `data_classification`: Per-rule data classification override. Same fields as defaults-level `data_classification`.
- `skip_data_classification`: When `true`, disables data classification for this rule. Cannot be combined with per-rule `data_classification`.
- `plugin_detection`: Per-rule plugin detection settings. Overrides defaults. See PolicyPluginDetection fields below.
- `skip_plugin_detection`: When `true`, skips plugin detection for this rule. Mutually exclusive with `plugin_detection`.
- `finding_suppressions`: Per-rule finding suppression rules. See PolicyFindingSuppression fields below.
- `response_rewrites`: Optional list of response rewrite operations applied before forwarding the response to the client. Each entry specifies:
  - `action`: One of `REDACT`, `REMOVE_HEADER`, or `SET_HEADER`.
    - `REDACT`: Replace matching `pattern` in the response body with `replacement`.
    - `REMOVE_HEADER`: Strip a response header.
    - `SET_HEADER`: Set or overwrite a response header with a given value.
  - `pattern`: Regex pattern for `REDACT` action.
  - `replacement`: Replacement string for `REDACT` action.
  - `header`: Header name for `REMOVE_HEADER` and `SET_HEADER` actions.
  - `value`: Header value for `SET_HEADER` action.
- `webhook_events`: Optional list of webhook event types this rule should trigger notifications for. Omit or empty list to notify on all events. Valid values: `circuit_open`, `reload_failed`, `injection_detected`, `credential_detected`, `integrity_drift`, `admin_denied`.
- `payload_match`: Optional list of structured payload matching constraints. Allows matching based on protocol-level semantics rather than raw body content. Each entry specifies:
  - `protocol`: Protocol identifier (e.g., `jsonrpc`, `graphql`).
  - `method`: Method name to match (protocol-specific).
  - `operation`: Operation name to match.
  - `operation_type`: Operation type to match (e.g., `query`, `mutation`, `subscription` for GraphQL).
- `conditions`: Optional block with additional matching constraints. When present, the rule only matches if all conditions are also satisfied.
  - `scheme`: Required scheme (`http` or `https`). Case-insensitive.
  - `ports`: List of allowed destination ports.
- `enforce_dns_resolution`: Optional default requiring hostnames to resolve before evaluation for HTTP requests. Resolved IPs are recorded in audit logs.
- `secret_scopes`: Optional list of secret scope rules that further restrict when a secret ID may be materialized.

## Defaults Fields

In addition to `action`, `max_body_bytes`, and `enforce_dns_resolution`, the `defaults` block supports:

- `content_inspection`: Content inspection configuration.
  - `enable_builtin_patterns`: Enable built-in injection pattern library (ChatML, INST, instruction override).
  - `custom_patterns`: List of regex patterns to match against request bodies (implicit anchor: `any`).
  - `anchored_patterns`: List of pattern objects with explicit anchor modes:
    - `pattern`: Regex pattern string.
    - `anchor`: One of `any` (default), `start_of_message`, or `standalone`.
      - `any`: Match anywhere in the body (same as `custom_patterns`).
      - `start_of_message`: Match only in the first 500 characters.
      - `standalone`: Match only when the pattern occupies an entire line.
  - `scan_websocket_frames`: Enable content inspection of WebSocket text frames for injection patterns and data classification.
- `url_inspection`: URL and path security inspection.
  - `max_query_length`: Maximum query string length before blocking.
  - `max_url_length`: Maximum total URL length before blocking.
  - `max_path_length`: Maximum path length before blocking (reason code `path_length_exceeded`).
  - `block_base64_values`: Block query values that look like Base64-encoded data.
  - `entropy_threshold`: Shannon entropy threshold for query parameter values.
  - `min_value_length`: Minimum value length before entropy/Base64 analysis applies.
  - `path_entropy_threshold`: Shannon entropy threshold for path segments.
  - `block_path_traversal`: Block path traversal patterns (`../`, encoded variants). Reason code `path_traversal_blocked`.
  - `block_double_encoding`: Block double percent-encoding (`%25XX`). Reason code `double_encoding_blocked`.
  - `block_invalid_percent_encoding`: Block requests with invalid percent-encoded sequences (e.g., `%ZZ`). Triggers `invalid_percent_encoding_blocked`.
- `block_dns_exfiltration`: Enable DNS exfiltration detection via subdomain entropy analysis.
- `dns_entropy_threshold`: Entropy threshold for DNS labels (default 4.0).
- `dns_min_label_length`: Minimum DNS label length for exfiltration detection (default 20).
- `max_response_scan_bytes`: Maximum response body size to scan (default 64KB).
- `max_bytes_per_host_per_session`: Per-host per-session byte budget for data exfiltration detection.
- `max_tokens_per_session`: Maximum cumulative LLM tokens per session before requests are denied with `token_budget_exceeded`.
- `scan_streaming_responses`: Enable or disable streaming response scanning for chunked/SSE responses (default `true`). Can also be set inside `content_inspection` for more granular control.
- `injection_scoring`: Heuristic injection scoring configuration.
  - `mode`: `binary` (default, deny on any pattern match) or `score` (weighted scoring with threshold).
  - `deny_threshold`: Score threshold above which requests are denied (default 1.0). Only used when mode is `score`.
  - `log_threshold`: Score threshold above which audit logs include scoring details. Must not exceed `deny_threshold`.
  - `entropy_weight`: Weight multiplier for Shannon entropy signal (default 0.1).
  - `entropy_baseline`: Entropy level below which no contribution is made (default 4.5).
  - `category_weights`: Optional list of category weight overrides. Each entry has `category` (one of `delimiter_injection`, `instruction_override`, `role_assumption`, `prompt_leaking`, `jailbreak`, `encoding_markers`) and `weight` (non-negative number).

See [security.md](security.md#injection-detection) for detailed configuration guidance.

- `ml_classifier`: Optional ML-based injection classifier (requires ONNX Runtime on classpath).
  - `enabled`: Boolean, default `false`.
  - `model_path`: Path to the ONNX model file (required when enabled).
  - `tokenizer_path`: Path to a HuggingFace `tokenizer.json` file. When set and DJL HuggingFace Tokenizers is on the classpath, OAG uses proper subword tokenization (WordPiece/BPE). When absent or DJL is unavailable, falls back to raw char-code encoding. The tokenizer must match the ONNX model — switching tokenizers requires a model trained with the same tokenizer.
  - `trigger_mode`: When to invoke the ML classifier. `always` (default) runs ML on every request. `uncertain_only` skips ML when the heuristic score is already decisive (below `uncertain_low` or above `uncertain_high`).
  - `uncertain_low`: Lower bound of the uncertainty band (default 0.3). Heuristic scores below this skip ML.
  - `uncertain_high`: Upper bound of the uncertainty band (default 0.8). Heuristic scores above this skip ML.
  - `confidence_threshold`: ML confidence threshold, 0-1 (default 0.5).
  - `max_length`: Maximum token sequence length (default 512).

See [security.md](security.md#ml-classifier-optional) for ML classifier setup and performance guidance.

- `outbound_credential_detection`: Boolean. When `true`, scan outbound request bodies for leaked credentials (AWS keys, GitHub PATs, Slack tokens, bearer tokens). See [security.md](security.md#outbound-credential-detection).
- `data_classification`: Data classification configuration for sensitive data detection.
  - `enable_builtin_patterns`: Enable built-in sensitive data patterns (financial, credentials, PII).
  - `custom_patterns`: List of additional regex patterns.
  - `categories`: List of categories to scan (`financial`, `credentials`, `pii`). Empty = all.
  - `scan_responses`: Boolean. When `true`, also scan response bodies.

See [security.md](security.md#data-classification) for built-in pattern details.

- `plugin_detection`: Default plugin detection settings applied to all rules. See PolicyPluginDetection fields below.
- `finding_suppressions`: Default finding suppression rules. See PolicyFindingSuppression fields below.

### PolicyPluginDetection Fields

- `enabled`: Enable plugin detection.
- `detector_ids`: Only run these detector IDs. If omitted, all loaded detectors run.
- `exclude_detector_ids`: Exclude these detector IDs from running.
- `scan_responses`: Also scan response bodies with plugin detectors.
- `deny_severity_threshold`: Auto-deny findings at or above this severity (`low`, `medium`, `high`, `critical`), independent of `RecommendedAction.DENY`.

### PolicyFindingSuppression Fields

- `detector_id`: Suppress findings from this detector ID.
- `finding_type`: Suppress findings of this type (e.g., `prompt_injection`, `credential`).
- `pattern`: Suppress findings whose evidence matches this regex pattern.
- `hosts`: Only suppress for these hosts.

## Host Matching

- Exact host match for `api.example.com`.
- Wildcard match for `*.example.com`.
- Raw IP literals can be denied even if they match a host rule.

## Redirect Handling

- Redirects are treated as new requests when redirect enforcement is enabled.
- Each redirect target must independently pass policy when redirect enforcement is enabled.
  Redirect semantics follow HTTP guidance. [RFC9110] [RFC7231]
  Redirect enforcement applies to HTTP responses only; CONNECT tunneling does not follow redirects.

## Retry Configuration

Per-rule retry configuration for upstream connection failures:

```yaml
allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    retry:
      max_retries: 3
      retry_delay_ms: 200
```

Fields:
- `max_retries`: Maximum number of retry attempts after the initial connection failure. Must be > 0.
- `retry_delay_ms`: Delay in milliseconds between retry attempts. Must be > 0. Defaults to 100ms if omitted.

Retry only applies to upstream TCP connection failures. Once a request has been sent, failures are not retried. When retries occur, the `retry_count` field in the audit event records the number of retry attempts made (0 = no retries needed).

## Policy Hashing

OAG emits a policy hash in audit logs to link decisions to the exact policy version used at runtime.

Policy bundles package policies with `policy_hash` and optional signatures. See [Policy Bundles](#policy-bundles) below.

## Policy Includes

Policies can reference other policy files using the `includes` field. Included files are resolved relative to the parent policy file and their `allow`, `deny`, and `secret_scopes` rules are merged into the main policy.

```yaml
version: 1
includes:
  - ./vendor/openai-rules.yaml
  - ./deny-lists/cloud-metadata.yaml

defaults:
  action: deny

allow:
  - id: local_rule
    host: api.example.com
    methods: [GET]
    paths: [/*]
```

- Include paths are resolved relative to the directory containing the parent policy file.
- Included files may themselves include other files (nested includes).
- Maximum include depth is 3 levels.
- Circular includes are detected and produce an error.
- Missing include files produce an error.
- The `version` and `defaults` fields from included files are ignored; only rules are merged.
- Include resolution happens before validation, so merged rules are validated together.
- Policy bundles do not support includes.

## Secret Provider Notes (Runtime)

Policy only defines secret IDs. Runtime configuration controls how those secrets are materialized:

- `env` provider reads `OAG_SECRET_<ID>` by default (override with `--secret-prefix`).
- `file` provider reads `<id>.secret` and optional `<id>.secret.version` from the secret dir.

Secret files are runtime concerns and do not change policy evaluation.

## Policy Bundles

Policy bundles package a policy document with metadata, a policy hash, and an optional signature. Bundles are designed for governance workflows where policies are generated, signed, and distributed as a single artifact.

### Bundle Format

Bundle files are JSON or YAML with the following fields:

- `bundle_version`: bundle schema version (current: `1`)
- `created_at`: ISO-8601 timestamp of bundle creation
- `policy`: embedded policy document
- `policy_hash`: SHA-256 hash of the normalized policy
- `signing` (optional):
  - `algorithm`: `ed25519`
  - `key_id`: optional key identifier
  - `signature`: base64 signature of `policy_hash`

Example:

```yaml
bundle_version: 1
created_at: "2026-02-23T00:00:00Z"
policy_hash: "abc123..."
policy:
  version: 1
  defaults:
    action: DENY
  allow:
    - id: openai_api
      host: api.openai.com
      methods: [POST]
      paths: [/v1/*]
      secrets: [OPENAI_KEY]
signing:
  algorithm: ed25519
  key_id: "policy-root-1"
  signature: "Base64SignatureHere"
```

Bundle files follow the same extension rules as policies: `.yaml` / `.yml` for YAML, `.json` for JSON.

### Creating a Bundle

```bash
oag bundle --policy policy.yaml --out policy.bundle.json
```

Sign with an Ed25519 private key (PKCS8 PEM or base64):

```bash
oag bundle --policy policy.yaml --out policy.bundle.json --sign-key ./keys/policy-private.pem --key-id policy-root-1
```

### Verifying a Bundle

Use `oag verify` with the Ed25519 public key (X.509 PEM or base64):

```bash
oag verify --bundle policy.bundle.json --public-key ./keys/policy-public.pem
```

`oag run`, `oag doctor`, `oag explain`, and `oag test` accept the same bundle file path via `--policy`.

### Bundle Enforcement

- If `--policy-require-signature` is set, OAG requires a signature and a public key.
- If a public key is provided and the policy file is not a bundle, OAG fails fast.
- Bundle signatures are verified against `policy_hash`, and OAG verifies that `policy_hash` matches the normalized policy.

### Key Format Notes

- Private keys: Ed25519 PKCS8 PEM or raw base64-encoded PKCS8 bytes.
- Public keys: Ed25519 X.509 PEM or raw base64-encoded X.509 bytes.

If you use PEM files, include the standard headers:

- `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----`
- `-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----`

## Policy Hot-Reload

OAG can automatically reload the policy file when it changes on disk. This enables updating rules without restarting the proxy, which is useful for long-running sessions and deployment pipelines that push policy updates.

### Enabling Hot-Reload

Pass the `--watch` flag to `oag run`:

```bash
oag run --policy policy.yaml --watch --log audit.jsonl
```

With `--watch` active, OAG monitors the policy file using the operating system's file notification service (`WatchService`). When the file is modified, OAG:

1. Re-reads the policy file from disk
2. Validates the new policy (schema, rules, patterns)
3. Normalizes and hashes the new policy
4. Atomically swaps the active policy snapshot

If validation fails, the current policy remains active and no traffic is disrupted.

### Debouncing

File modifications are debounced with a 500ms window. Rapid successive writes (e.g., editor save-then-format) are collapsed into a single reload. This prevents unnecessary reloads from editors that write files in multiple steps.

### Reload Behavior

- **Atomic swap**: The policy snapshot is replaced using `@Volatile` and `@Synchronized` access. In-flight requests that already captured a policy reference continue using the old policy. New requests use the updated policy.
- **Validation-first**: The new policy is fully validated before replacing the old one. Invalid policies are rejected with an error audit event; the proxy continues operating with the previous valid policy.
- **History tracking**: Each successful policy change is recorded in `PolicyService.policyHistory()` with a hash and timestamp.
- **No-op on unchanged**: If the file is modified but the normalized policy hash is identical, no swap occurs and `changed` is `false` in the audit event.

### Reload Audit Events

Every reload attempt (success or failure) emits a `policy_reload` audit event:

Successful reload (policy changed):

```json
{
  "event_type": "policy_reload",
  "schema_version": "3",
  "oag_version": "0.1.0",
  "previous_policy_hash": "abc123...",
  "new_policy_hash": "def456...",
  "changed": true,
  "success": true,
  "agent_id": "agent-1",
  "session_id": "session-1",
  "timestamp": "2026-02-23T12:00:00Z"
}
```

Successful reload (no change):

```json
{
  "event_type": "policy_reload",
  "schema_version": "3",
  "previous_policy_hash": "abc123...",
  "new_policy_hash": "abc123...",
  "changed": false,
  "success": true
}
```

Failed reload (invalid policy):

```json
{
  "event_type": "policy_reload",
  "schema_version": "3",
  "previous_policy_hash": "abc123...",
  "new_policy_hash": null,
  "changed": false,
  "success": false,
  "error_message": "Policy validation failed:\n- allow[0].host: Missing or empty"
}
```

### File Watcher Details

- **Scope**: Only the policy file itself is monitored. Changes to other files in the same directory are ignored.
- **Platform**: Uses Java NIO `WatchService`, which maps to `inotify` on Linux, `FSEvents` on macOS, and `ReadDirectoryChangesW` on Windows.
- **Thread**: The watcher runs as a coroutine on `Dispatchers.IO`. It does not block the proxy's request-handling threads.
- **Shutdown**: The watcher is closed when the proxy shuts down. The coroutine is cancelled via `watchJob?.cancel()`.

### Hot-Reload Verbose Logging

When `--verbose` is also active, reload events are logged to stderr:

```
policy reloaded changed=true hash=def456...
```

On failure:

```
policy reload failed: Policy validation failed: ...
```

### Hot-Reload Limitations

- **Bundle files**: When using signed policy bundles (`.bundle.json`), the watcher monitors the bundle file. The signature is re-verified on each reload.
- **Config-dir mode**: When using `--config-dir`, the watcher monitors `<config-dir>/policy.yaml`.
- **No remote sources**: The watcher only monitors local files. For remote policy sources, use an external tool to download and write the file locally.

## Policy Linting and Conflict Detection

OAG includes a built-in policy linter that detects common misconfigurations, shadowed rules, and overlapping scopes. Use it in CI to catch policy issues before deployment.

### Lint CLI Usage

```bash
oag lint --policy policy.yaml
```

JSON output for CI integration:

```bash
oag lint --policy policy.yaml --json
```

Exit codes:
- `0` — no warnings
- `1` — warnings found (or invalid policy)

### Lint Rules

**UNSAFE_DEFAULT_ALLOW** — `defaults.action` is set to `allow`, which disables default-deny security posture. Requests not matched by any deny rule will be forwarded.

**SHADOWED_RULE** — A later rule in the same section (allow or deny) is unreachable because an earlier rule matches a superset of its scope.

```yaml
allow:
  - id: broad-rule
    host: "*.example.com"
  - id: narrow-rule          # SHADOWED: *.example.com already covers api.example.com
    host: api.example.com
```

The linter checks host, method, and path coverage. Rules with `ip_ranges`, `conditions`, `body_match`, `header_match`, `query_match`, or `payload_match` constraints are considered narrower and cannot shadow other rules.

**OVERLAPPING_RULES** — An allow rule and a deny rule could match the same request. OAG evaluates deny rules first, so the deny rule takes precedence — but this overlap may indicate unintended policy behavior.

```yaml
allow:
  - id: allow-api
    host: api.example.com
    methods: [GET, POST]
deny:
  - id: deny-post
    host: api.example.com
    methods: [POST]           # OVERLAP: POST matches both rules (deny wins)
```

**UNUSED_SECRET_REF** — A rule references a secret ID that is not defined in `secret_scopes`. This usually means the secret will never be materialized.

```yaml
allow:
  - id: openai-rule
    host: api.openai.com
    secrets: [openai-key]     # WARNING: no secret_scopes entry for 'openai-key'
secret_scopes: []
```

**UNREACHABLE_ALLOW** — An allow rule is unreachable because a deny rule matches all of its traffic. Since deny rules are evaluated first, the allow rule will never be reached.

**UNSAFE_REGEX** — A regex pattern in a rule (body_match, header_match, query_match, payload_match, content_inspection, anchored_patterns, response_rewrites, or data_classification) uses patterns that may be vulnerable to ReDoS (nested quantifiers, excessive length).

### Lint JSON Output Schema

```json
{
  "ok": true,
  "warning_count": 0,
  "warnings": []
}
```

With warnings:

```json
{
  "ok": false,
  "warning_count": 2,
  "warnings": [
    {
      "code": "SHADOWED_RULE",
      "message": "allow rule 'narrow-rule' is shadowed by earlier rule 'broad-rule'",
      "rule_id": "narrow-rule",
      "rule_index": 1,
      "section": "allow"
    },
    {
      "code": "UNUSED_SECRET_REF",
      "message": "allow rule 'openai-rule' references secret 'openai-key' not defined in secret_scopes",
      "rule_id": "openai-rule",
      "rule_index": 0,
      "section": "allow"
    }
  ]
}
```

### Lint CI Integration

Add a lint step to your CI pipeline:

```yaml
# GitHub Actions example
- name: Lint OAG policy
  run: oag lint --policy policy.yaml --json
```

The command exits with code 1 when warnings are found, failing the CI step.

Lint works with policy bundles and signature verification:

```bash
oag lint --policy policy.bundle.json --policy-public-key ./keys/policy-public.pem --policy-require-signature
```

## Agent Profiles

Optional per-agent access control. Profiles restrict which rules an agent can use:

```yaml
agent_profiles:
  - id: code-agent
    allowed_rules: [github_api, npm_registry]
    max_requests_per_minute: 60
    max_body_bytes: 1048576
    tags: [ci, automated]

  - id: research-agent
    denied_rules: [internal_api]
    max_requests_per_minute: 120
```

Fields:
- `id`: Profile identifier (required). Matched against `--agent` at runtime.
- `allowed_rules`: Whitelist of rule IDs this agent can use. When set, only listed rules apply.
- `denied_rules`: Blacklist of rule IDs blocked for this agent.
- `max_requests_per_minute`: Optional rate limit per agent.
- `max_body_bytes`: Optional body size limit for this agent.
- `tags`: Optional labels for categorization.

When an agent is blocked by its profile, the reason code is `agent_profile_denied`.

## References

- HTTP semantics and redirect behavior: RFC 9110. [RFC9110]
- CONNECT method behavior: RFC 9110. [RFC9110]
- SSRF and proxy bypass patterns: OWASP SSRF Prevention Cheat Sheet. [OWASP-SSRF]

See [concepts.md](concepts.md#references) for full reference list.

## Examples

See [examples/policy-examples.md](examples/policy-examples.md) for ready-to-use policy recipes.
