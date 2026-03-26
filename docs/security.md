# Security & Content Inspection

OAG provides layered defenses against prompt injection, data exfiltration, credential leakage, and path-based attacks at the HTTP proxy level.

## Scope

OAG inspects:

- **HTTP request/response bodies** (plaintext, or HTTPS with TLS interception enabled)
- **URL query parameters and path segments**
- **DNS hostname labels**
- **WebSocket text frames** (when TLS interception is enabled)

OAG cannot inspect:

- HTTPS bodies without `tls_inspect` enabled per-rule
- Non-HTTP egress outside OAG scope
- Semantic prompt injection (pattern-based detection, not semantic analysis)

### CONNECT Tunnel Security Model

When a CONNECT request is allowed but `tls_inspect: true` is not set on the matching rule, OAG establishes an opaque byte relay between the agent and the upstream server. In this mode:

- **Host-level security only** — policy evaluation, DNS resolution, IP blocking, rate limiting, velocity spike detection, and agent profile enforcement all apply to the CONNECT target
- **No content inspection** — the TLS-encrypted tunnel is opaque; body inspection, credential detection, data classification, and plugin detection cannot run
- **No response scanning** — response redaction, body matching, and token extraction are impossible

This is an inherent property of TLS tunneling, not an OAG limitation. To enable full content inspection on HTTPS traffic, set `tls_inspect: true` on the rule and configure a CA bundle. This enables MITM TLS interception where OAG decrypts, inspects, and re-encrypts traffic.

## Injection Detection

### Built-in Patterns

Enable via `defaults.content_inspection.enable_builtin_patterns: true`.

| Category | Detects |
|---|---|
| `delimiter_injection` | ChatML (`<\|im_start\|>`, `<\|im_end\|>`), `[INST]`/`[/INST]`, `<system>` XML, `[SYSTEM]` bracket variant, Llama 3 control tokens (`<\|start_header_id\|>`, `<\|eot_id\|>`), Alpaca format, `<\|endoftext\|>` |
| `instruction_override` | "ignore previous instructions", "system override", "developer mode" |
| `role_assumption` | "you are now a...", "act as...", "pretend to be..." |
| `prompt_leaking` | "reveal your system prompt", "what is your prompt" |
| `jailbreak` | "do anything now", "no restrictions", "bypass filters" |
| `encoding_markers` | Base64/hex/Unicode escape sequences, ROT13 decode directives |

NFKC Unicode normalization and zero-width character stripping applied before matching. Denied with `injection_detected`.

### Custom Patterns

```yaml
defaults:
  content_inspection:
    custom_patterns:
      - "(?i)api[_-]?key\\s*[:=]"
    anchored_patterns:
      - pattern: "ignore\\s+previous"
        anchor: standalone         # only match on own line
      - pattern: "<\\|im_start\\|>"
        anchor: start_of_message   # first 500 chars only
```

Anchor modes: `any` (default — anywhere), `start_of_message` (first 500 chars), `standalone` (entire line). Custom patterns always trigger deny regardless of scoring mode.

### Heuristic Scoring

Weighted scoring instead of binary deny-on-any-match:

```yaml
defaults:
  injection_scoring:
    mode: score           # or "binary" (default)
    deny_threshold: 2.0
    log_threshold: 0.5
    entropy_weight: 0.1
    entropy_baseline: 4.5
    category_weights:
      - category: jailbreak
        weight: 2.0
      - category: role_assumption
        weight: 0.2
```

Default weights: `delimiter_injection`=1.0, `instruction_override`=0.8, `prompt_leaking`=0.7, `jailbreak`=0.9, `role_assumption`=0.6, `encoding_markers`=0.5.

Audit fields when scoring: `injection_score` (numeric), `injection_signals` (list of `category:pattern_name`).

### ML Classifier (Optional)

ONNX-based classifier (e.g., DeBERTa) alongside heuristic scoring:

```yaml
defaults:
  ml_classifier:
    enabled: true
    model_path: /models/deberta-injection.onnx
    tokenizer_path: /models/tokenizer.json   # parsed but not used at runtime (reserved for future use)
    confidence_threshold: 0.8
    max_length: 512
```

Requires ONNX Runtime on classpath (not bundled). Tokenization uses raw char-code encoding internally — no external tokenizer library (e.g., DJL HuggingFace Tokenizers) is required or used. Silently disabled if unavailable. Combined score = max(heuristic, ML). Set `trigger_mode: uncertain_only` to skip ML inference when the heuristic score is already decisive (outside the `uncertain_low`/`uncertain_high` band), reducing latency on high-throughput deployments.

### Per-Rule Overrides

```yaml
allow:
  - id: trusted_internal
    skip_content_inspection: true    # bypass all inspection

  - id: sensitive_endpoint
    content_inspection:              # rule-specific patterns
      custom_patterns: ["(?i)tell me a secret"]
      scan_streaming_responses: true
```

`skip_content_inspection` and `content_inspection` are mutually exclusive.

## Sensitive Data Detection

### Outbound Credential Detection

Scan outbound request bodies for leaked credentials:

```yaml
defaults:
  outbound_credential_detection: true
```

Detects: AWS access keys (`AKIA`/`ASIA`/`AROA`/`AIPA`/`ANPA`/`ANVA`/`APKA`...), GitHub PATs (`ghp_`/`gho_`/`ghu_`/`ghs_...`), Slack tokens (`xox[bpoas]-...`), bearer tokens, private key headers (`-----BEGIN ... PRIVATE KEY-----`), JWT tokens (`eyJ...` three-segment base64url format), generic API key patterns (`api_key`, `apikey`, `secret_key`, `access_token` key=value assignments). Denied with `outbound_credential_detected`. Per-rule bypass: `skip_outbound_credential_detection: true`.

### Data Classification

Scan request bodies for sensitive data patterns:

```yaml
defaults:
  data_classification:
    enable_builtin_patterns: true
    categories: [financial, credentials, pii]
    scan_responses: true
```

Built-in patterns by category:

| Category | Patterns |
|---|---|
| `financial` | Visa/Mastercard/Amex credit cards, IBAN |
| `credentials` | AWS access keys, GitHub PATs, Slack tokens, bearer tokens |
| `pii` | SSN, email addresses, US phone numbers |

Denied with `sensitive_data_detected`. Per-rule: `data_classification: {...}` to override, or `skip_data_classification: true` to bypass.

## Path Analysis

URL path security checks configured in `defaults.url_inspection`:

```yaml
defaults:
  url_inspection:
    block_path_traversal: true
    block_double_encoding: true
    max_path_length: 2048
    path_entropy_threshold: 4.5
```

| Check | Reason Code | Detects |
|---|---|---|
| Path traversal | `path_traversal_blocked` | `../`, `..\`, percent-encoded variants (`%2e%2e`) |
| Double encoding | `double_encoding_blocked` | `%25XX` patterns (double percent-encoding) |
| Path length | `path_length_exceeded` | Paths exceeding `max_path_length` |
| Path entropy | Part of URL inspection | High-entropy path segments |

## Exfiltration Guards

### URL Query Parameters

```yaml
defaults:
  url_inspection:
    max_query_length: 2048
    max_url_length: 8192
    block_base64_values: true
    entropy_threshold: 4.0
    min_value_length: 40
```

Values shorter than `min_value_length` skip entropy/Base64 analysis. Denied with `url_exfiltration_blocked`.

### DNS Labels

```yaml
defaults:
  block_dns_exfiltration: true
  dns_entropy_threshold: 4.0
```

Labels shorter than 20 characters are ignored. High-entropy labels blocked with `dns_exfiltration_blocked`. Checked for both HTTP and CONNECT requests.

### Per-Domain Data Budget

```yaml
defaults:
  max_bytes_per_host_per_session: 10485760
```

Tracks bytes sent per host per session. Requires `--session`. Denied with `data_budget_exceeded`.

## Body Matching

### Request Bodies

```yaml
allow:
  - id: openai_chat
    body_match:
      contains: ["model"]
      patterns: ["\"model\":\\s*\"gpt-[34]"]
```

AND semantics — all entries must match. Unicode normalized. Denied with `body_match_failed`.

### Response Bodies

```yaml
allow:
  - id: openai_chat
    response_body_match:
      patterns: ["<\\|im_start\\|>"]
    skip_response_scanning: false
```

Fixed-length responses within `max_response_scan_bytes` (default 64KB). Detected as `response_injection_detected`.

### Streaming Responses

Chunked and SSE responses scanned using:
- **Aho-Corasick automaton** for `contains` literals — O(n) matching across chunk boundaries
- **Regex accumulation buffer** for `patterns` — up to `max_response_scan_bytes`

Enforcement mode: response truncated at detection point. Dry-run mode: full response relayed, patterns recorded in audit.

Control: `defaults.scan_streaming_responses`, `defaults.content_inspection.scan_streaming_responses`, or per-rule `content_inspection.scan_streaming_responses`.

## Rate Limiting

Per-rule token bucket:

```yaml
allow:
  - id: openai_api
    rate_limit:
      requests_per_second: 10
      burst: 20
```

Denied with `rate_limited` (HTTP 429). Rate limiters reconfigured on policy reload.

## Session Tracking

When `--session` is set, OAG tracks per-session state:

- **Request timestamps** in a 60-second sliding window, per session and per host (used to derive velocity; not persistent counts)
- **Body hashes** (SHA-256 prefix, last 64 requests)
- **Rolling injection score** from heuristic scoring
- **Request velocity** (RPS derived from the sliding window, per session and per host)

Useful for detecting: multi-request injection campaigns, replay attacks (repeated body hashes), velocity anomalies.

## WebSocket Inspection

For WebSocket connections (via CONNECT + TLS interception), OAG inspects text frames for:

- Injection patterns (same built-in and custom patterns as HTTP body inspection)
- Outbound credentials
- Sensitive data

Audit events include WebSocket session data: frame counts (client/server), detected patterns, data classification matches.

## TLS Interception

Enable per-rule HTTPS body inspection:

```yaml
allow:
  - id: openai_api
    host: api.openai.com
    tls_inspect: true
```

Runtime: `--tls-inspect --tls-ca-cert-path ./oag-ca.pem`. Ephemeral CA generated at startup. The CA certificate is written to disk when `--tls-ca-cert-path` is set; the CA private key is never persisted and stays in memory only. Host certificates cached per hostname. Decrypted traffic passes through the full inspection pipeline.

Client trust: `curl --cacert oag-ca.pem`, `NODE_EXTRA_CA_CERTS=oag-ca.pem`, Python `session.verify = "oag-ca.pem"`, Java `keytool -importcert -alias oag-ca -file oag-ca.pem -keystore truststore.jks`.

Without `tls_inspect`, CONNECT tunnels use opaque relay (no body inspection).

## Reason Codes

All reason codes emitted by OAG:

| Code | Description |
|---|---|
| `allowed_by_rule` | Request matched an allow rule |
| `denied_by_rule` | Request matched a deny rule |
| `no_match_default_allow` | No rule matched, default action is allow |
| `no_match_default_deny` | No rule matched, default action is deny |
| `raw_ip_literal_blocked` | Raw IP address used as destination (`--block-ip-literals`) |
| `dns_resolved_private_range_blocked` | DNS resolved to private/loopback range (`--block-private-resolved-ips`) |
| `dns_resolution_failed` | DNS lookup failed (`enforce_dns_resolution`) |
| `redirect_target_denied` | Redirect target failed policy check (`--enforce-redirect-policy`) |
| `upstream_connection_failed` | Could not connect to upstream |
| `body_too_large` | Request body exceeds `max_body_bytes` |
| `secret_materialization_failed` | Secret injection failed |
| `signature_invalid` | Request signature verification failed |
| `rate_limited` | Token bucket exhausted for matched rule |
| `velocity_spike_detected` | Request velocity exceeded spike threshold |
| `token_budget_exceeded` | Session token budget exhausted |
| `body_match_failed` | Body did not match allow rule's `body_match` |
| `url_exfiltration_blocked` | High-entropy or Base64 data in URL query parameters |
| `dns_exfiltration_blocked` | High-entropy subdomain label |
| `injection_detected` | Injection pattern matched in request body |
| `response_injection_detected` | Injection pattern found in response body |
| `data_budget_exceeded` | Per-host session byte budget exceeded |
| `circuit_open` | Circuit breaker is open for this host |
| `invalid_request` | Malformed or invalid HTTP request |
| `outbound_credential_detected` | Credentials detected in outbound request body |
| `sensitive_data_detected` | PII or financial data detected in request body |
| `path_traversal_blocked` | Path traversal attack detected in URL |
| `double_encoding_blocked` | Double-encoded characters detected in URL |
| `invalid_percent_encoding_blocked` | URL contains invalid percent-encoded sequences |
| `path_length_exceeded` | URL path exceeds maximum allowed length |
| `plugin_detected` | Plugin detector triggered denial |
| `response_plugin_detected` | Response plugin detector triggered denial |
| `agent_profile_denied` | Agent profile blocked the request |
