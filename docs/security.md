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
    tokenizer_path: /models/tokenizer.json   # loads HuggingFace tokenizer when DJL is on classpath
    confidence_threshold: 0.8
    max_length: 512
```

Requires ONNX Runtime on classpath (not bundled). When `tokenizer_path` is set and DJL HuggingFace Tokenizers is on the classpath, OAG uses proper subword tokenization matching the model's training vocabulary. Without DJL, falls back to raw char-code encoding. The tokenizer and model must match — a model trained with WordPiece tokenization requires the corresponding `tokenizer.json`. Silently disabled if ONNX Runtime is unavailable. Combined score = max(heuristic, ML). Set `trigger_mode: uncertain_only` to skip ML inference when the heuristic score is already decisive (outside the `uncertain_low`/`uncertain_high` band), reducing latency on high-throughput deployments.

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

## Escalation Detection

Session-aware detection of multi-turn injection campaigns. Requires `--session`.

```yaml
defaults:
  injection_scoring:
    mode: score
    deny_threshold: 0.3
    escalation:
      enabled: true
      window_size: 5
      deny_patterns:
        - sustained_elevation
        - crescendo
        - saw_tooth_probing
        - periodic_testing
```

| Pattern | Detects |
|---|---|
| `sustained_elevation` | All scores in the window above threshold (persistent low-grade probing) |
| `crescendo` | Strictly increasing scores across the window (gradual escalation) |
| `saw_tooth_probing` | Scores alternating above and below threshold (attacker probing threshold boundaries) |
| `periodic_testing` | High injection scores appearing at regular turn intervals (fixed-cadence probing) |

When an escalation pattern is detected, the current request's injection score is boosted by 1.5x. If the boosted score exceeds `deny_threshold`, the request is denied with `injection_escalation_detected` and `injection_escalating: true` in the audit. When the base score alone (without escalation boost) exceeds the threshold, the reason code remains `injection_detected`.

Audit fields: `injection_escalating`, `escalation_pattern`, `escalation_window_scores`, `escalation_window_size`.

## Hallucination Detection

Multi-signal risk scoring for LLM response integrity. Operates on response bodies in the response inspection pipeline.

```yaml
defaults:
  hallucination_check:
    enabled: true
    mode: observe
    deny_threshold: 0.8
    log_threshold: 0.3
    impossible_claims: true
    logprob_analysis: true
```

### Signals

| Signal | Source | What It Detects |
|---|---|---|
| `impossible_claims` | Response body | Nonexistent software versions, hallucinated model names, impossible dates. 210 patterns via Aho-Corasick + regex |
| `url_verification` | Response body | URLs that return 404 or are unreachable (HEAD request via SSRF-safe client) |
| `package_verification` | Response body | Package names not found in pip/npm registries |
| `logprob_analysis` | Response JSON | Low model confidence from logprob values (maps mean logprob to 0-1 risk score) |
| `claim_contradiction` | Session history | Claims that contradict previous responses in the same session (URLs, version strings, numeric assertions) |
| `tool_receipt_verification` | Session history | LLM claims that don't match cached tool response data |
| `external_nli` | External endpoint | Score from an external NLI verification service |

### Modes

- `observe` — record findings in audit, never block. Use for monitoring before enforcing.
- `enforce` — block requests when the aggregated hallucination score exceeds `deny_threshold`. Denied with `hallucination_detected`.

### Session-Aware Signals

`claim_contradiction` and `tool_receipt_verification` require `--session`. Claims from responses flagged by other signals are excluded from the cache to prevent cache poisoning.

## Topic Classification

Deny or allow requests based on the topic of the user's message, determined by an external classifier.

```yaml
defaults:
  topic_classification:
    enabled: true
    endpoint_url: "https://classifier.example.com/api"
    denied_topics: ["violence", "illegal_activity"]
    confidence_threshold: 0.8
    on_error: deny
```

### How It Works

1. OAG extracts the last user message from chat-format JSON bodies (`messages[].role == "user"`). Falls back to the full body if not chat format.
2. Sends `{"text": "...", "topics": [...]}` to the classifier endpoint.
3. Classifier returns `{"topic": "violence", "confidence": 0.95}`.
4. If the topic matches a denied topic (case-insensitive) with confidence above threshold, the request is denied with `topic_denied`.

### Topic Modes

- `denied_topics` — deny if the classified topic is in the list.
- `allowed_topics` — deny if the classified topic is NOT in the list.

These are mutually exclusive.

### Error Handling

- `on_error: deny` — block the request if the classifier fails or times out.
- `on_error: allow` — allow the request through on classifier failure.

Per-rule: `topic_classification: {...}` to override, or `skip_topic_classification: true` to bypass.

Audit field: `topic_classification` with `topic`, `confidence`, `action`, `endpoint_latency_ms`, `error`.

## External Judge

Route uncertain-confidence injection decisions to an external judgment endpoint for additional analysis.

```yaml
defaults:
  external_judge:
    enabled: true
    endpoint_url: "https://judge.example.com/api"
    trigger_mode: uncertain_only
    on_error: skip
    deny_threshold: 0.7
```

### How It Works

1. OAG runs its heuristic injection scorer first.
2. In `uncertain_only` mode, the judge is only invoked when the heuristic produces no decision. In `always` mode, it runs on every request.
3. OAG sends `{"request_body": "...", "host": "...", "path": "...", "method": "...", "injection_score": 0.4}` with HMAC-SHA256 signing.
4. Judge returns `{"score": 0.85, "decision": "deny", "reason": "suspicious content"}`.
5. If the judge score exceeds `deny_threshold` or the decision is `"deny"`, the request is blocked.

### Error Handling

- `on_error: deny` — block the request if the judge fails.
- `on_error: allow` — allow the request through on judge failure.
- `on_error: skip` — proceed with the heuristic result only.

Audit field: `content_inspection.external_judge` with `score`, `decision`, `source`, `latency_ms`, `reason`, `error`.

## Code Security Analysis

Scan LLM-generated code in responses for common vulnerability patterns. Operates on response bodies via the plugin detection pipeline.

Register the bundled detector and enable response scanning:

```bash
oag run --policy policy.yaml \
  --plugin-provider com.mustafadakhel.oag.inspection.content.CodeSecurityDetectorProvider
```

```yaml
defaults:
  plugin_detection:
    enabled: true
    scan_responses: true
```

### Code Extraction

OAG extracts code blocks from response bodies using two strategies:

- **Markdown fences** — `` ```lang ... ``` `` blocks with optional language tags
- **JSON tool calls** — `code` fields from OpenAI/Anthropic tool_call response formats

Extracted blocks are scanned up to 524 KB per response body.

### Vulnerability Rules

| Rule ID | CWE | Severity | Description |
|---|---|---|---|
| `sql_fstring` | CWE-89 | HIGH | Python f-string used in SQL query |
| `sql_concat_execute` | CWE-89 | HIGH | String concatenation in SQL execute call |
| `cmd_shell_true` | CWE-78 | HIGH | subprocess call with `shell=True` |
| `cmd_os_system` | CWE-78 | HIGH | `os.system()` call |
| `cmd_eval_exec` | CWE-78 | HIGH | `eval()` or `exec()` call |
| `deser_pickle` | CWE-502 | HIGH | Insecure pickle deserialization |
| `deser_yaml_unsafe` | CWE-502 | HIGH | `yaml.load()` without SafeLoader |
| `crypto_md5` | CWE-327 | MEDIUM | Weak MD5 hash usage |
| `secret_assignment` | CWE-798 | HIGH | Hardcoded secret in variable assignment |

The `deser_yaml_unsafe` rule is context-aware — a code block is only flagged if any `yaml.load()` call lacks `SafeLoader` or `safe_load` on its line.

### Performance

- **Time budget**: 50 ms per response (configurable). Scanning stops when the budget is exhausted.
- **ReDoS protection**: All regex patterns are validated against adversarial input at construction time.

### Audit

Findings surface in audit events via existing plugin infrastructure:

- `response_plugin_detector_ids: ["code-security"]`
- `response_plugin_finding_count: <N>`

Each finding includes evidence: `pattern` (rule ID), `cwe`, `code_block_source` (`markdown_fence` or `json_tool_call`), and `language` (when detected).

## Session Tracking

When `--session` is set, OAG tracks per-session state:

- **Request timestamps** in a 60-second sliding window, per session and per host (used to derive velocity; not persistent counts)
- **Body hashes** (SHA-256 prefix, last 64 requests)
- **Dense scored turns** — every turn's injection score with turn index, used for escalation detection
- **Claim fingerprints** — URLs, version strings, and numeric assertions from responses, used for contradiction detection
- **Tool response excerpts** — cached tool response data keyed by request path + method
- **Request velocity** (RPS derived from the sliding window, per session and per host)

Useful for detecting: multi-request injection campaigns, replay attacks (repeated body hashes), velocity anomalies, escalation patterns, claim contradictions.

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
| `injection_escalation_detected` | Escalation boost caused injection denial (base score alone would not have denied) |
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
| `hallucination_detected` | Hallucination risk score exceeded threshold |
| `topic_denied` | Request topic matched a denied topic |
| `response_schema_invalid` | Response body failed schema validation |
