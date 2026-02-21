# CLI

This document captures the CLI surface for OAG.

## `oag run`

Start the OAG proxy server. Enforces egress policy, materializes secrets, and records audit events for all HTTP and HTTPS traffic.

Example:

```bash
oag run --policy policy.yaml --port 8080 --log audit.jsonl
```

With an agent command:

```bash
oag run --policy policy.yaml -- <agent-command>
```

Config-dir form:

```bash
oag run --config-dir ./config --port 8080
```

With admin server for health/metrics (see [observability.md](observability.md#admin-server)):

```bash
oag run --policy policy.yaml --admin-port 9090
```

With policy hot-reload (see [configuration.md](configuration.md)):

```bash
oag run --policy policy.yaml --watch --log audit.jsonl
```

## `oag explain`

Evaluate a single request against a policy without running an agent.

Example:

```bash
oag explain --policy policy.yaml --request "POST https://api.openai.com/v1/chat/completions"
```

Machine-readable output:

```bash
oag explain --policy policy.yaml --request "POST https://api.openai.com/v1/chat/completions" --json
```

Verbose machine-readable output (includes normalized request tuple):

```bash
oag explain --policy policy.yaml --request "POST https://api.openai.com/v1/chat/completions" --json --verbose
```

Bundle verification flags:

```bash
oag explain --policy policy.bundle.json --policy-public-key ./keys/policy-public.pem --policy-require-signature --request "POST https://api.openai.com/v1/chat/completions"
```

## `oag doctor`

Validate policy files and runtime configuration.

Example:

```bash
oag doctor --policy policy.yaml
```

Config-dir form:

```bash
oag doctor --config-dir ./config
```

Machine-readable output:

```bash
oag doctor --policy policy.yaml --json
```

Verbose machine-readable output (includes effective config):

```bash
oag doctor --policy policy.yaml --json --verbose
```

If the policy path points to a bundle, `doctor --json --verbose` includes a `bundle` object with signature metadata and verification status.

## `oag test`

Policy test harness for CI verification.

Example:

```bash
oag test policy.yaml --cases cases.yaml
```

Config-dir form:

```bash
oag test --config-dir ./config --cases cases.yaml
```

Machine-readable output:

```bash
oag test policy.yaml --cases cases.yaml --json
```

Verbose machine-readable output (includes per-case decisions):

```bash
oag test policy.yaml --cases cases.yaml --json --verbose
```

Bundle verification flags:

```bash
oag test --policy policy.bundle.json --policy-public-key ./keys/policy-public.pem --policy-require-signature --cases cases.yaml
```

## `oag run --verbose`

Enable runtime diagnostic output to stderr. Emits timestamped lines for each request showing policy decisions, upstream connections, secret materialization, and response details.

Example:

```bash
oag run --policy policy.yaml --verbose -- <agent-command>
```

Sample output:

```
[2026-02-23T12:00:00Z] starting oag 0.1.0 on 0.0.0.0:8080
[2026-02-23T12:00:00Z] policy loaded hash=abc123...
[2026-02-23T12:00:01Z] http POST https://api.openai.com:443/v1/chat/completions
[2026-02-23T12:00:01Z] policy action=allow reason=allowed_by_rule rule=allow-openai
[2026-02-23T12:00:01Z] secret materialization secrets=1
[2026-02-23T12:00:01Z] upstream connected api.openai.com:443
[2026-02-23T12:00:02Z] response status=200 bytes_in=1234 duration_ms=850
```

## `oag run --dry-run`

Observe policy violations without blocking requests. Note: dry-run still evaluates raw IP and DNS resolution checks but only logs decisions.

Example:

```bash
oag run --policy policy.yaml --dry-run -- <agent-command>
```

## `oag run --block-ip-literals`

Deny raw IPv4/IPv6 literal destinations before connect.

Example:

```bash
oag run --policy policy.yaml --block-ip-literals -- <agent-command>
```

## `oag run --enforce-redirect-policy`

Re-evaluate HTTP redirect targets and block denied hops.

Example:

```bash
oag run --policy policy.yaml --enforce-redirect-policy -- <agent-command>
```

## `oag run --block-private-resolved-ips`

Deny requests when DNS resolution yields private/special-purpose addresses.

Example:

```bash
oag run --policy policy.yaml --block-private-resolved-ips -- <agent-command>
```

## `oag run --connect-timeout-ms / --read-timeout-ms`

Set upstream connect/read socket timeouts (milliseconds).

Example:

```bash
oag run --policy policy.yaml --connect-timeout-ms 5000 --read-timeout-ms 30000 -- <agent-command>
```

## `oag run --secret-provider / --secret-dir / --secret-prefix`

Select the secret provider backend. Supported values are `env` (default), `file`, and `oauth2`.

Example (env provider, default):

```bash
oag run --policy policy.yaml --secret-provider env -- <agent-command>
```

Override the environment variable prefix (default `OAG_SECRET_`):

```bash
oag run --policy policy.yaml --secret-prefix OAG_SECRET_ -- <agent-command>
```

Example (file provider):

```bash
oag run --policy policy.yaml --secret-provider file --secret-dir ./secrets -- <agent-command>
```

## `oag run --policy-public-key / --policy-require-signature`

Require signed policy bundles and verify with a public key:

```bash
oag run --policy policy.bundle.json --policy-public-key ./keys/policy-public.pem --policy-require-signature -- <agent-command>
```

## `oag run --otel-exporter / --otel-endpoint / --otel-headers`

Enable OpenTelemetry log export for audit events. Exporters:

- `none` (default)
- `otlp_http`
- `otlp_grpc`
- `stdout`

Notes:

- `otlp_http` and `otlp_grpc` require `--otel-endpoint`.
- `stdout` ignores `--otel-endpoint` and prints log records to stdout.

Example (OTLP/HTTP):

```bash
oag run --policy policy.yaml --otel-exporter otlp_http --otel-endpoint http://localhost:4318/v1/logs
```

Example (OTLP/HTTP with headers):

```bash
oag run --policy policy.yaml --otel-exporter otlp_http --otel-endpoint https://otel.example.com/v1/logs --otel-headers "Authorization=Bearer $TOKEN"
```

Override exporter timeout and service name:

```bash
oag run --policy policy.yaml --otel-exporter otlp_http --otel-endpoint http://localhost:4318/v1/logs --otel-timeout-ms 5000 --otel-service-name oag-prod
```

Example (stdout exporter):

```bash
oag run --policy policy.yaml --otel-exporter stdout
```

## `oag hash`

Print the policy hash:

```bash
oag hash --policy policy.yaml
```

JSON output:

```bash
oag hash --policy policy.yaml --json
```

Example output:

```json
{"ok":true,"policy_hash":"<sha256>","bundle":{"version":1,"created_at":"<iso8601>","policy_hash":"<sha256>","signing_algorithm":"ed25519","signing_key_id":"key-1","signature_status":"verified"}}
```

Failure example:

```json
{"ok":false,"error_code":"config_error","error":"policy bundle signature verification failed"}
```

Bundle verification flags:

```bash
oag hash --policy policy.bundle.json --policy-public-key ./keys/policy-public.pem --policy-require-signature
```

## `oag bundle`

Create a policy bundle:

```bash
oag bundle --policy policy.yaml --out policy.bundle.json
```

Create and sign a bundle:

```bash
oag bundle --policy policy.yaml --out policy.bundle.json --sign-key ./keys/policy-private.pem --key-id policy-root-1
```

JSON output:

```bash
oag bundle --policy policy.yaml --out policy.bundle.json --json
```

JSON output schema:

```json
{"ok": true, "bundle_path": "<path>", "policy_hash": "<sha256>", "signed": false}
```

## `oag verify`

Verify a bundle signature:

```bash
oag verify --bundle policy.bundle.json --public-key ./keys/policy-public.pem
```

JSON output:

```bash
oag verify --bundle policy.bundle.json --public-key ./keys/policy-public.pem --json
```

Example output:

```json
{"ok":true,"policy_hash":"<sha256>","bundle":{"version":1,"created_at":"<iso8601>","policy_hash":"<sha256>","signing_algorithm":"ed25519","signing_key_id":"key-1","signature_status":"verified"}}
```

## `oag simulate`

Evaluate a synthetic request against a policy using explicit flags. Unlike `explain` (which takes a URL string), `simulate` accepts individual `--method`, `--host`, `--path`, `--scheme`, and `--port` flags for precise control.

Example:

```bash
oag simulate --policy policy.yaml --method POST --host api.openai.com --path /v1/chat/completions
```

With explicit scheme and port:

```bash
oag simulate --policy policy.yaml --method GET --host api.example.com --path /v1/models --scheme http --port 8080
```

JSON output:

```bash
oag simulate --policy policy.yaml --method POST --host api.openai.com --path /v1/chat --json
```

Defaults:
- `--scheme`: `https`
- `--port`: `443` (https) or `80` (http)
- `--path`: `/`

Text output:

```
action=allow reason=allowed_by_rule rule=openai
request: POST https://api.openai.com:443/v1/chat
eligible_secrets: OPENAI_KEY
```

JSON output:

```json
{"ok":true,"action":"allow","reason_code":"allowed_by_rule","rule_id":"openai","request":{"scheme":"https","host":"api.openai.com","port":443,"method":"POST","path":"/v1/chat"},"eligible_secrets":["OPENAI_KEY"]}
```

When the request is denied or matches a rule without secrets, the `eligible_secrets` field is omitted.

### Batch Mode

Evaluate multiple requests from a YAML/JSON file:

```bash
oag simulate --policy policy.yaml --batch requests.yaml
```

JSON output:

```bash
oag simulate --policy policy.yaml --batch requests.yaml --json
```

Batch input format:

```yaml
requests:
  - name: openai-chat
    method: POST
    host: api.openai.com
    path: /v1/chat/completions
  - name: github-repos
    method: GET
    host: api.github.com
    path: /repos
  - method: GET
    host: evil.com
    path: /exfil
```

Each request supports: `method` (required), `host` (required), `path` (default `/`), `scheme` (default `https`), `port` (default 443/80), `name` (optional label).

Text output:

```
openai-chat: action=allow reason=allowed_by_rule rule=openai
github-repos: action=allow reason=allowed_by_rule rule=github
GET https://evil.com:443/exfil: action=deny reason=no_match_default_deny rule=-

total=3 allow=2 deny=1
rule hits:
  openai: 1
  github: 1
  (no rule): 1
```

JSON output:

```json
{"ok":true,"total":3,"allow_count":2,"deny_count":1,"rule_hit_counts":{"(no rule)":1,"github":1,"openai":1},"results":[...]}
```

## `oag lint`

Lint a policy file for common issues. See [configuration.md](configuration.md) for details.

```bash
oag lint --policy policy.yaml
```

JSON output:

```bash
oag lint --policy policy.yaml --json
```

Exit code 1 when warnings are found.

JSON output schema:

```json
{"ok": true, "warning_count": 0, "warnings": []}
```

Each warning object has the following fields:

| Field | Type | Description |
|---|---|---|
| `code` | string | Lint code string |
| `message` | string | Human-readable warning message |
| `rule_id` | string? | ID of the related rule (nullable) |
| `rule_index` | int? | Index of the related rule (nullable) |
| `section` | string? | Policy section the warning applies to (nullable) |

## `oag help`

Print command usage and flag summary.

Machine-readable output:

```bash
oag help --json
```

## `--config-dir` Path Rules

- default policy file: `<config-dir>/policy.yaml`
- run mode default log path: `<config-dir>/logs/audit.jsonl` (if `--log` is omitted)
- file secret provider default secret dir: `<config-dir>/secrets` (if `--secret-dir` is omitted)
- explicit `--policy` and `--log` override config-dir defaults

Bundle note:

- If you use a bundle, pass it explicitly via `--policy policy.bundle.json` (config-dir does not auto-detect bundles).

## JSON Output Schemas

`doctor --json`:

```json
{"ok":true,"policy_hash":"<sha256>","policy_path":"<path>"}
```

`doctor --json --verbose`:

```json
{"ok":true,"policy_hash":"<sha256>","policy_path":"<path>","effective_config":{"listen_host":"0.0.0.0","listen_port":8080,"max_threads":32,"dry_run":false,"block_ip_literals":false,"enforce_redirect_policy":false,"block_private_resolved_ips":false,"connect_timeout_ms":5000,"read_timeout_ms":30000,"secret_env_prefix":"OAG_SECRET_","secret_provider":"env","policy_require_signature":false,"otel_exporter":"none","otel_headers_keys":[],"otel_timeout_ms":10000,"otel_service_name":"oag"},"bundle":{"version":1,"created_at":"<iso8601>","policy_hash":"<sha256>","signing_algorithm":"ed25519","signing_key_id":"key-1","signature_status":"verified"}}
```

`explain --json`:

```json
{"ok":true,"action":"allow|deny","reason_code":"<code>","rule_id":"<id>|null"}
```

`explain --json --verbose`:

```json
{"ok":true,"action":"allow|deny","reason_code":"<code>","rule_id":"<id>|null","request":{"scheme":"https","host":"api.example.com","port":443,"method":"POST","path":"/v1/*"}}
```

`test --json`:

```json
{"ok":true,"total":10,"passed":10,"failed":0,"failures":[]}
```

`test --json --verbose`:

```json
{"ok":false,"total":2,"passed":1,"failed":1,"failures":["case: expected(...) actual(...)"],"cases":[{"name":"case","ok":false,"expected_action":"allow","expected_reason":"allowed_by_rule","actual_action":"deny","actual_reason":"no_match_default_deny"}]}
```

`simulate --json`:

```json
{"ok":true,"action":"allow","reason_code":"allowed_by_rule","rule_id":"openai","request":{"scheme":"https","host":"api.openai.com","port":443,"method":"POST","path":"/v1/chat"},"eligible_secrets":["OPENAI_KEY"]}
```

`help --json`:

```json
{"commands":["run","doctor","explain","test","hash","bundle","verify","lint","simulate","diff","help"],"json_modes":["doctor","explain","test","hash","bundle","verify","lint","simulate","diff","help"]}
```

## Running OAG

### Native Binary

```bash
oag run --policy policy.yaml --port 8080 --log audit.jsonl
```

### Fat JAR

```bash
./gradlew shadowJar
java -jar oag-app/build/libs/oag-app-1.0-SNAPSHOT-all.jar run --policy policy.yaml --port 8080 --log audit.jsonl
```

### Development (Gradle)

```bash
./gradlew :oag-app:run --args="run --policy policy.yaml --port 8080 --log audit.jsonl"
```

File provider example:

```bash
./gradlew :oag-app:run --args="run --policy policy.yaml --port 8080 --log audit.jsonl --secret-provider file --secret-dir ./secrets"
```

Provide secrets as environment variables using `OAG_SECRET_<ID>` when using the `env` provider. See [getting-started.md](getting-started.md) for setup details.

## `oag run --agent / --session`

Set agent and session identifiers for audit correlation:

```bash
oag run --policy policy.yaml --agent my-agent --session session-123
```

- `--agent <id>`: Agent identifier. Recorded in every audit event. Used for agent profile matching.
- `--session <id>`: Session identifier. Enables per-session tracking (data budgets, velocity, request counts).

## `oag run --max-threads`

Set the maximum thread pool size for request handling:

```bash
oag run --policy policy.yaml --max-threads 64
```

- `--max-threads <n>`: Maximum number of threads. Default: 32.

## `oag run --circuit-breaker-threshold / --circuit-breaker-reset-ms / --circuit-breaker-half-open-probes`

Configure the per-host circuit breaker. See [operations.md](operations.md#circuit-breaker) for details.

```bash
oag run --policy policy.yaml --circuit-breaker-threshold 5 --circuit-breaker-reset-ms 30000 --circuit-breaker-half-open-probes 2
```

- `--circuit-breaker-threshold <n>`: Consecutive failures before opening. Default: 5.
- `--circuit-breaker-reset-ms <ms>`: Time in OPEN state before probing. Default: 30000.
- `--circuit-breaker-half-open-probes <n>`: Successful probes required before closing. Default: 1.

## `oag run --drain-timeout-ms`

Configure the graceful shutdown drain timeout. See [operations.md](operations.md#graceful-shutdown) for details.

```bash
oag run --policy policy.yaml --drain-timeout-ms 10000
```

- `--drain-timeout-ms <ms>`: Maximum time to wait for active connections to complete during shutdown. Default: 10000.

## `oag run --tls-inspect / --tls-ca-cert-path`

Enable TLS interception for CONNECT tunnels with `tls_inspect: true` in policy rules.

```bash
oag run --policy policy.yaml --tls-inspect --tls-ca-cert-path ./oag-ca.pem --log audit.jsonl
```

- `--tls-inspect`: Generate an ephemeral CA at startup and enable TLS interception for matching rules.
- `--tls-ca-cert-path <file>`: Write the CA certificate in PEM format to this path. Clients must trust this CA.

See [security.md](security.md#tls-interception) for client trust setup and detailed configuration.

## `oag run --mtls-ca-cert / --mtls-keystore / --mtls-keystore-password`

Require mTLS client certificate authentication:

```bash
oag run --policy policy.yaml --mtls-ca-cert ./ca.pem --mtls-keystore ./keystore.p12 --mtls-keystore-password changeit
```

- `--mtls-ca-cert <path>`: CA certificate PEM file for verifying client certificates.
- `--mtls-keystore <path>`: PKCS12 keystore file containing the proxy's server certificate and key.
- `--mtls-keystore-password <password>`: Keystore password.

## `oag run --require-signed-headers / --agent-signing-secret`

Require agents to cryptographically sign request headers:

```bash
oag run --policy policy.yaml --require-signed-headers --agent-signing-secret "shared-secret"
```

- `--require-signed-headers`: Reject requests without valid HMAC signatures.
- `--agent-signing-secret <secret>`: Shared secret for HMAC-SHA256 header verification.

## `oag run --inject-request-id / --request-id-header`

Inject a unique request ID into upstream request headers and audit events.

```bash
oag run --policy policy.yaml --inject-request-id --log audit.jsonl
```

With a custom header name:

```bash
oag run --policy policy.yaml --inject-request-id --request-id-header X-Trace-Id --log audit.jsonl
```

- `--inject-request-id`: Generate a UUID-based request ID for each allowed request and inject it into upstream headers. The same ID is recorded in the `request_id` field of the audit event.
- `--request-id-header <name>`: Override the default header name (`X-Request-Id`). Only applies when `--inject-request-id` is set.

Request IDs are generated after policy evaluation and secret materialization, so denied requests do not receive request IDs. For MITM-intercepted CONNECT tunnels, each inner HTTP request gets its own request ID.

## `oag run --velocity-spike-threshold`

Detect abnormal request rate spikes per session:

```bash
oag run --policy policy.yaml --velocity-spike-threshold 3.0
```

- `--velocity-spike-threshold <n>`: Multiplier over baseline RPS before flagging. Default: 0 (disabled). Requires `--session`.

## `oag run --integrity-check-interval-s`

Enable periodic runtime integrity verification:

```bash
oag run --policy policy.yaml --integrity-check-interval-s 300
```

- `--integrity-check-interval-s <n>`: Seconds between integrity checks. Default: 0 (disabled). Emits `integrity_check` audit events.

## `oag diff`

Compare two policy files and report differences:

```bash
oag diff policy-v1.yaml policy-v2.yaml
```

Output:

```
allow added: new_api
allow removed: old_api
allow changed: openai_api
  methods: [POST] -> [POST, GET]
defaults changed:
  max_body_bytes: 1048576 -> 2097152
```

JSON output:

```bash
oag diff policy-v1.yaml policy-v2.yaml --json
```

```json
{
  "ok": true,
  "has_changes": true,
  "defaults_changed": true,
  "defaults_details": ["max_body_bytes: 1048576 -> 2097152"],
  "rule_diffs": [
    {"section": "allow", "id": "new_api", "change": "added", "details": []},
    {"section": "allow", "id": "old_api", "change": "removed", "details": []},
    {"section": "allow", "id": "openai_api", "change": "changed", "details": ["methods: [POST] -> [POST, GET]"]}
  ],
  "secret_scope_diffs": []
}
```

Both policies are loaded, validated, and normalized before comparison. Rules are matched by their `id` field. Rules without IDs are compared by structural equality.

## `oag run --pool-max-idle / --pool-idle-timeout-ms`

Enable HTTP connection pooling for upstream connections:

```bash
oag run --policy policy.yaml --pool-max-idle 8 --pool-idle-timeout-ms 60000
```

- `--pool-max-idle <n>`: Maximum idle connections per upstream host:port. Set to 0 (default) to disable pooling.
- `--pool-idle-timeout-ms <ms>`: Idle timeout in milliseconds before pooled connections are evicted. Default: 60000.

When enabled, the proxy reuses upstream TCP connections for HTTP requests to the same host:port. Connections are returned to the pool after a complete response with defined framing (Content-Length or chunked Transfer-Encoding) and no `Connection: close` header. A background thread evicts expired connections.

Connection pooling only applies to HTTP forward proxy requests. CONNECT tunnels and MITM-intercepted connections are not pooled.

Pool metrics (`oag_pool_hits_total`, `oag_pool_misses_total`, `oag_pool_evictions_total`) are available on the admin metrics endpoint.

## `oag run --log-max-size-mb / --log-max-files / --log-compress`

Enable audit log rotation for the JSONL log file:

```bash
oag run --policy policy.yaml --log audit.jsonl --log-max-size-mb 50 --log-max-files 5
```

With gzip compression of rotated files:

```bash
oag run --policy policy.yaml --log audit.jsonl --log-max-size-mb 50 --log-max-files 10 --log-compress
```

- `--log-max-size-mb <n>`: Maximum size in megabytes before the active log file is rotated. Set to 0 (default) to disable rotation.
- `--log-max-files <n>`: Maximum number of rotated log files to retain. Default: 5. Oldest files beyond this limit are deleted on rotation.
- `--log-compress`: Gzip-compress rotated log files (`.gz` suffix). Only applies when `--log-max-size-mb` is set.
- `--log-rotation-interval <interval>`: Time-based rotation (`daily`, `hourly`). Used alongside or instead of size-based rotation.

Rotated files are named `<logfile>.1`, `<logfile>.2`, etc. (or `<logfile>.1.gz` with compression). File `.1` is always the most recent rotation. When a new rotation occurs, existing rotated files are shifted (`.1` becomes `.2`, etc.) and the oldest file beyond `--log-max-files` is deleted.

Log rotation only applies when writing to a file (`--log`). Stdout logging is never rotated.

## `oag run --admin-port / --admin-allowed-ips / --admin-token / --admin-reload-cooldown-ms`

Enable the admin HTTP server:

```bash
oag run --policy policy.yaml --admin-port 9090 --admin-token mysecret --admin-allowed-ips 127.0.0.1,10.0.0.0/8
```

- `--admin-port <n>`: Port for the admin server. Disabled when omitted.
- `--admin-allowed-ips <list>`: Comma-separated IPs or CIDR ranges. Non-listed IPs receive 403.
- `--admin-token <token>`: Bearer token required for admin requests.
- `--admin-reload-cooldown-ms <ms>`: Minimum interval between reloads. Default: 5000.

See [observability.md](observability.md#admin-server) for endpoints.

## `oag run --webhook-url / --webhook-events / --webhook-timeout-ms / --webhook-signing-secret`

Enable webhook notifications for operational events:

```bash
oag run --policy policy.yaml --webhook-url https://hooks.example.com/oag --webhook-events circuit_open,reload_failed --webhook-signing-secret mysecret
```

- `--webhook-url <url>`: Destination URL for webhook POST requests.
- `--webhook-events <list>`: Comma-separated event types to send. Available: `circuit_open`, `reload_failed`, `injection_detected`, `credential_detected`, `integrity_drift`, `admin_denied`.
- `--webhook-timeout-ms <ms>`: HTTP timeout for webhook delivery. Default: 5000.
- `--webhook-signing-secret <secret>`: HMAC-SHA256 signing key. Adds `X-OAG-Signature: sha256=<hex>` header.

See [observability.md](observability.md#webhook-notifications) for payload format.

## `oag run --policy-url / --policy-fetch-interval-s`

Periodically fetch policies from a remote URL:

```bash
oag run --policy /tmp/cached.yaml --policy-url https://config.example.com/policy.yaml --policy-fetch-interval-s 300
```

- `--policy-url <url>`: Remote URL to fetch the policy from.
- `--policy-fetch-interval-s <n>`: Fetch interval in seconds. Default: 60.

See [operations.md](operations.md#remote-policy-fetching) for behavior details.

## Policy Reload

See [operations.md](operations.md#policy-reload-at-runtime) for runtime reload triggers (admin endpoint, SIGHUP, file watcher).

## All `oag run` Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--policy <path>` | string | required | Policy file path |
| `--config-dir <path>` | string | — | Convention-based config directory |
| `--port <n>` | int | 8080 | Listen port |
| `--log <path>` | string | stdout | Audit log file path |
| `--agent <id>` | string | — | Agent identifier for audit |
| `--session <id>` | string | — | Session identifier for tracking |
| `--max-threads <n>` | int | 32 | Thread pool size |
| `--verbose` | flag | off | Debug output to stderr |
| `--dry-run` | flag | off | Log violations without blocking |
| `--watch` | flag | off | Hot-reload policy on file change |
| `--connect-timeout-ms <ms>` | int | 5000 | Upstream connect timeout |
| `--read-timeout-ms <ms>` | int | 30000 | Upstream read timeout |
| `--drain-timeout-ms <ms>` | long | 10000 | Graceful shutdown drain timeout |
| `--secret-provider <type>` | string | env | Secret backend (`env`, `file`, `oauth2`) |
| `--secret-dir <path>` | string | — | Secret files directory (file provider) |
| `--secret-prefix <prefix>` | string | OAG_SECRET_ | Env var prefix (env provider) |
| `--oauth2-token-url <url>` | string | — | OAuth2 token endpoint |
| `--oauth2-client-id <id>` | string | — | OAuth2 client ID |
| `--oauth2-client-secret <secret>` | string | — | OAuth2 client secret |
| `--oauth2-scope <scope>` | string | — | OAuth2 scope |
| `--policy-public-key <path>` | string | — | Ed25519 public key for bundle verification |
| `--policy-require-signature` | flag | off | Require signed policy bundles |
| `--block-ip-literals` | flag | off | Deny raw IP destinations |
| `--block-private-resolved-ips` | flag | off | Deny DNS resolving to private IPs |
| `--enforce-redirect-policy` | flag | off | Re-evaluate redirect targets |
| `--tls-inspect` | flag | off | Enable TLS interception |
| `--tls-ca-cert-path <path>` | string | — | Write ephemeral CA cert to this path |
| `--mtls-ca-cert <path>` | string | — | Client CA cert for mTLS |
| `--mtls-keystore <path>` | string | — | Server keystore for mTLS |
| `--mtls-keystore-password <pw>` | string | — | Keystore password |
| `--require-signed-headers` | flag | off | Require HMAC-signed headers |
| `--agent-signing-secret <secret>` | string | — | Shared HMAC signing secret |
| `--inject-request-id` | flag | off | Inject UUID request ID |
| `--request-id-header <name>` | string | X-Request-Id | Request ID header name |
| `--admin-port <n>` | int | — | Admin server port |
| `--admin-allowed-ips <list>` | string | — | Comma-separated allowed IPs/CIDRs |
| `--admin-token <token>` | string | — | Admin bearer token |
| `--admin-reload-cooldown-ms <ms>` | long | 5000 | Min interval between reloads |
| `--circuit-breaker-threshold <n>` | int | 5 | Failures before opening |
| `--circuit-breaker-reset-ms <ms>` | long | 30000 | OPEN → HALF_OPEN timeout |
| `--circuit-breaker-half-open-probes <n>` | int | 1 | Probes before closing |
| `--pool-max-idle <n>` | int | 0 | Max idle connections per host |
| `--pool-idle-timeout-ms <ms>` | long | 60000 | Idle connection timeout |
| `--log-max-size-mb <n>` | int | 0 | Max log file size before rotation |
| `--log-max-files <n>` | int | 5 | Max rotated log files |
| `--log-compress` | flag | off | Gzip rotated logs |
| `--log-rotation-interval <val>` | string | — | Time-based rotation (daily, hourly) |
| `--webhook-url <url>` | string | — | Webhook destination URL |
| `--webhook-events <list>` | string | — | Comma-separated event types |
| `--webhook-timeout-ms <ms>` | int | 5000 | Webhook HTTP timeout |
| `--webhook-signing-secret <secret>` | string | — | Webhook HMAC signing key |
| `--velocity-spike-threshold <n>` | double | 0 | RPS spike multiplier |
| `--policy-url <url>` | string | — | Remote policy fetch URL |
| `--policy-fetch-interval-s <n>` | long | 60 | Remote fetch interval |
| `--integrity-check-interval-s <n>` | long | 0 | Integrity check interval |
| `--otel-exporter <type>` | string | none | OTel exporter type |
| `--otel-endpoint <url>` | string | — | OTel collector endpoint |
| `--otel-headers <list>` | string | — | OTel headers (key=value,key=value) |
| `--otel-timeout-ms <ms>` | int | 10000 | OTel export timeout |
| `--otel-service-name <name>` | string | oag | OTel service name |
| `--plugin-provider <list>` | string | — | Comma-separated list of fully-qualified class names for plugin detector providers. Providers are loaded via reflection and must implement `DetectorProvider`. |
