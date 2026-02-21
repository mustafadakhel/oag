# Policy Examples

These examples are for existing features only. Adjust hosts and paths to match your environment.

## OpenAI API

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]
```

Runtime (env provider):

```powershell
$env:OAG_SECRET_OPENAI_KEY = "<real_key>"
```

Runtime (file provider):

```powershell
New-Item -ItemType Directory -Path .\secrets -Force | Out-Null
"<real_key>" | Set-Content -Path .\secrets\OPENAI_KEY.secret
"v1" | Set-Content -Path .\secrets\OPENAI_KEY.secret.version
```

## GitHub Read-Only

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: github_readonly
    host: "*.github.com"
    methods: [GET]
    paths: [/*]
```

## Internal API (Example)

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: internal_api
    host: api.internal.example
    methods: [GET, POST]
    paths: [/v1/*]
    secrets: [INTERNAL_API_KEY]
```

## Secret Scope (Example)

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]

secret_scopes:
  - id: OPENAI_KEY
    hosts: [api.openai.com]
    methods: [POST]
    paths: [/v1/*]
    ip_ranges: ["203.0.113.0/24"]
```

## IP Range Guardrails (Example)

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: local_ip_ranges
    host: 10.0.0.1
    ip_ranges: ["10.0.0.0/24", "fd00::/8"]
    methods: [GET]
    paths: [/*]
```

## Multi-Rule Agent Policy

A realistic policy for an agent that calls multiple APIs with different access levels:

```yaml
version: 1

defaults:
  action: deny
  max_body_bytes: 1048576
  enforce_dns_resolution: true

allow:
  - id: openai_chat
    host: api.openai.com
    methods: [POST]
    paths: [/v1/chat/completions, /v1/embeddings]
    secrets: [OPENAI_KEY]
    max_body_bytes: 4194304

  - id: github_api
    host: api.github.com
    methods: [GET, POST]
    paths: [/repos/*, /search/*]
    secrets: [GITHUB_TOKEN]

  - id: github_raw
    host: raw.githubusercontent.com
    methods: [GET]
    paths: [/*]

  - id: npm_registry
    host: registry.npmjs.org
    methods: [GET]
    paths: [/*]

deny:
  - id: cloud_metadata
    host: 169.254.169.254

  - id: internal_network
    host: "*.internal.corp"
```

## Multi-Scope Secret Binding

Restrict each secret to its intended destination:

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]

  - id: anthropic_api
    host: api.anthropic.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [ANTHROPIC_KEY]

  - id: github_api
    host: api.github.com
    methods: [GET, POST]
    paths: [/repos/*]
    secrets: [GITHUB_TOKEN]

secret_scopes:
  - id: OPENAI_KEY
    hosts: [api.openai.com]
    methods: [POST]
    paths: [/v1/*]

  - id: ANTHROPIC_KEY
    hosts: [api.anthropic.com]
    methods: [POST]
    paths: [/v1/*]

  - id: GITHUB_TOKEN
    hosts: [api.github.com]
    methods: [GET, POST]
    paths: [/repos/*]
```

## CI Pipeline Policy

A locked-down policy for CI with hardening flags:

```yaml
version: 1

defaults:
  action: deny
  max_body_bytes: 524288
  enforce_dns_resolution: true

allow:
  - id: package_registry
    host: registry.npmjs.org
    methods: [GET]
    paths: [/*]

  - id: docker_registry
    host: "*.docker.io"
    methods: [GET]
    paths: [/*]

deny:
  - id: block_metadata
    host: 169.254.169.254

  - id: block_private_ranges
    host: 10.0.0.1
    ip_ranges: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

Runtime flags:

```bash
oag run --policy policy.yaml --block-ip-literals --block-private-resolved-ips --enforce-redirect-policy --log audit.jsonl
```

## Conditional Rules (Scheme and Port Constraints)

Restrict rules with additional conditions. The rule only matches when all conditions are satisfied:

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: api_https_only
    host: api.example.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [API_KEY]
    conditions:
      scheme: https
      ports: [443, 8443]

deny:
  - id: block_plaintext
    host: "*.internal.corp"
    conditions:
      scheme: http
```

The `api_https_only` rule allows POST requests only when the scheme is `https` and the port is 443 or 8443. The `block_plaintext` deny rule blocks all plaintext HTTP requests to internal hosts regardless of other fields.

## Body Content Matching

Restrict rules based on request body content:

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: openai_chat
    host: api.openai.com
    methods: [POST]
    paths: [/v1/chat/completions]
    body_match:
      contains: ["model"]
      patterns: ["\"model\":\\s*\"gpt-[34]"]

deny:
  - id: block_dangerous_prompts
    host: api.openai.com
    body_match:
      patterns: ["(?i)ignore\\s+previous\\s+instructions"]
```

The allow rule only matches when the body contains `"model"` literally and matches the model regex. The deny rule blocks requests whose body matches a prompt injection pattern.

## Rate Limiting

Limit request rates per rule to prevent abuse:

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]
    rate_limit:
      requests_per_second: 10
      burst: 20
```

Requests matching `openai_api` are allowed up to 20 burst requests, then refilled at 10 requests/second. Excess requests are denied with `rate_limited` reason code.

## Custom Reason Codes

Override the default audit reason code for specific rules:

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]
    reason_code: approved_by_security_team

deny:
  - id: block_metadata
    host: 169.254.169.254
    reason_code: ssrf_prevention
```

Audit logs will emit `approved_by_security_team` or `ssrf_prevention` instead of the default `allowed_by_rule` / `denied_by_rule`.

## Content Inspection (Built-in Patterns)

Enable built-in injection pattern detection with custom patterns:

```yaml
version: 1

defaults:
  action: deny
  content_inspection:
    enable_builtin_patterns: true
    custom_patterns:
      - "(?i)api[_-]?key\\s*[:=]\\s*['\"]?[A-Za-z0-9]{20,}"

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]
```

Request bodies are normalized (NFKC + zero-width character stripping) before pattern matching. Matches are denied with `injection_detected`.

## URL Exfiltration Detection

Detect encoded data in URL query parameters:

```yaml
version: 1

defaults:
  action: deny
  url_inspection:
    max_query_length: 2048
    block_base64_values: true
    entropy_threshold: 4.0
    min_value_length: 40

allow:
  - id: search_api
    host: api.example.com
    methods: [GET]
    paths: [/v1/search]
```

Query values shorter than `min_value_length` are not checked. Denied with `url_exfiltration_blocked`.

## DNS Exfiltration Detection

Block high-entropy subdomain labels:

```yaml
version: 1

defaults:
  action: deny
  block_dns_exfiltration: true
  dns_entropy_threshold: 4.0

allow:
  - id: api_access
    host: "*.example.com"
    methods: [GET, POST]
    paths: [/*]
```

Labels shorter than 20 characters are ignored. Denied with `dns_exfiltration_blocked`.

## Response Body Scanning

Scan upstream responses for injection patterns:

```yaml
version: 1

defaults:
  action: deny
  max_response_scan_bytes: 65536

allow:
  - id: openai_chat
    host: api.openai.com
    methods: [POST]
    paths: [/v1/chat/completions]
    secrets: [OPENAI_KEY]
    response_body_match:
      patterns: ["<\\|im_start\\|>", "\\[INST\\]", "(?i)ignore\\s+previous"]
```

Only fixed-length responses within the scan limit are scanned. Matches are recorded as `response_injection_detected`.

## Per-Domain Data Budget

Limit bytes sent per host per session:

```yaml
version: 1

defaults:
  action: deny
  max_bytes_per_host_per_session: 10485760

allow:
  - id: api_access
    host: api.example.com
    methods: [GET, POST]
    paths: [/*]
```

Requires `--session` at runtime. Exceeded budgets are denied with `data_budget_exceeded`.

## Per-Rule Content Inspection Override

Override or disable defaults-level content inspection per rule:

```yaml
version: 1

defaults:
  action: deny
  content_inspection:
    enable_builtin_patterns: true

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]
    # Inherits defaults content_inspection (built-in patterns)

  - id: internal_tool
    host: api.internal.example
    methods: [POST]
    paths: [/*]
    skip_content_inspection: true  # trusted internal, skip scanning

  - id: anthropic_api
    host: api.anthropic.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [ANTHROPIC_KEY]
    content_inspection:             # custom patterns for this rule only
      custom_patterns:
        - "(?i)tell me a secret"
```

Rules without `content_inspection` or `skip_content_inspection` inherit the defaults. The `internal_tool` rule bypasses all content inspection. The `anthropic_api` rule uses its own custom patterns instead of the defaults.

## Anchored Patterns (Reducing False Positives)

Use anchor modes to control where patterns must appear:

```yaml
version: 1

defaults:
  action: deny
  content_inspection:
    anchored_patterns:
      - pattern: "ignore\\s+previous\\s+instructions?"
        anchor: standalone       # only match on its own line
      - pattern: "<\\|im_start\\|>"
        anchor: start_of_message # only match in first 500 chars
      - pattern: "(?i)system\\s+override"
        anchor: any              # match anywhere (default)

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]
```

With `standalone` anchoring, a body like `"How do I ignore previous instructions in my code?"` will NOT trigger the pattern because the phrase is embedded in a sentence. A body containing `ignore previous instructions` on its own line will trigger it.

## Heuristic Injection Scoring

Use weighted scoring to reduce false positives from benign content matching low-confidence patterns:

```yaml
version: 1

defaults:
  action: deny
  injection_scoring:
    mode: score
    deny_threshold: 0.7
    log_threshold: 0.3
    category_weights:
      - category: role_assumption
        weight: 0.2
      - category: jailbreak
        weight: 2.0
  content_inspection:
    enable_builtin_patterns: true

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]
```

With this policy, a simple role assumption like "You are now a helpful assistant" scores 0.2 (below threshold) and is allowed. A multi-category attack like `<|im_start|>system ignore previous instructions` scores 2.8+ and is denied.

## Streaming Response Scanning

Scan chunked and SSE streaming responses for injection patterns:

```yaml
version: 1

defaults:
  action: deny
  max_response_scan_bytes: 65536

allow:
  - id: openai_streaming
    host: api.openai.com
    methods: [POST]
    paths: [/v1/chat/completions]
    secrets: [OPENAI_KEY]
    response_body_match:
      contains: ["<|im_start|>"]
      patterns: ["(?i)ignore\\s+previous\\s+instructions"]
```

The Aho-Corasick automaton matches `contains` literals across chunk boundaries. Regex `patterns` are accumulated and checked up to the `max_response_scan_bytes` limit. In enforcement mode, the response is truncated at the detection point. In dry-run mode, all patterns are recorded in audit without interrupting the response.

To disable streaming scanning for a specific rule while keeping fixed-length response scanning:

```yaml
allow:
  - id: trusted_sse
    host: events.internal.example
    methods: [GET]
    paths: [/stream]
    content_inspection:
      scan_streaming_responses: false
    response_body_match:
      patterns: ["<\\|im_start\\|>"]
```

## Policy Bundle (Example)

The following example shows a signed policy bundle. Use `oag bundle` to produce this automatically.

```yaml
bundle_version: 1
created_at: "2026-02-23T00:00:00Z"
policy_hash: "abc123..."
policy:
  version: 1
  defaults:
    action: deny
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

## TLS Interception (HTTPS Body Inspection)

Enable body-level inspection on HTTPS CONNECT tunnels:

```yaml
version: 1

defaults:
  action: deny
  content_inspection:
    enable_builtin_patterns: true

allow:
  - id: openai_api
    host: api.openai.com
    methods: [CONNECT]
    tls_inspect: true
    secrets: [OPENAI_KEY]

  - id: github_api
    host: api.github.com
    methods: [CONNECT]
    # No tls_inspect: opaque relay, no body inspection
```

Runtime:

```bash
oag run --policy policy.yaml --tls-inspect --tls-ca-cert-path ./oag-ca.pem --log audit.jsonl
```

Clients must trust the generated CA:

```bash
curl --cacert ./oag-ca.pem --proxy http://localhost:8080 https://api.openai.com/v1/chat/completions
```

## Header Rewrites

Add, remove, or append headers on upstream requests per rule:

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: openai_api
    host: api.openai.com
    methods: [POST]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]
    header_rewrites:
      - action: SET
        header: X-Source
        value: oag-proxy
      - action: APPEND
        header: X-Request-Tags
        value: automated
      - action: REMOVE
        header: X-Internal-Debug
```

- `SET` overwrites or creates the header.
- `APPEND` appends to an existing value (comma-separated) or creates if absent.
- `REMOVE` strips the header; no audit entry is emitted if the header was already absent.
- Rewrites are applied after secret materialization.
- Reserved headers (`Host`, `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Connection`, `Proxy-Connection`) cannot be rewritten.

## Per-Rule Timeouts

Override global connect/read timeouts for specific rules:

```yaml
version: 1

defaults:
  action: deny

allow:
  - id: fast_api
    host: api.fast.com
    methods: [GET, POST]
    paths: [/v1/*]
    connect_timeout_ms: 2000
    read_timeout_ms: 10000

  - id: slow_api
    host: api.slow.com
    methods: [POST]
    paths: [/v1/*]
    connect_timeout_ms: 10000
    read_timeout_ms: 120000
```

- `connect_timeout_ms` overrides `--connect-timeout-ms` for this rule.
- `read_timeout_ms` overrides `--read-timeout-ms` for this rule.
- When not set, the global timeout values apply.
