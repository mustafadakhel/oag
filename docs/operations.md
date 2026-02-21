# Operations

## Running OAG

### Native Binary

Download the platform-specific binary from Releases and run directly:

```bash
oag run --policy policy.yaml --port 8080 --log audit.jsonl
```

No JVM required. Instant startup, no cold-path delays.

### Fat JAR

```bash
java -jar oag-app-all.jar run --policy policy.yaml --port 8080 --log audit.jsonl
```

Requires JDK 21+. First few requests may show JVM warm-up latency (typically < 150ms).

### Local Development

```bash
./gradlew :oag-app:run --args="run --policy policy.yaml --port 8080 --log audit.jsonl"
```

Point agents to `HTTP_PROXY=http://localhost:8080` and `HTTPS_PROXY=http://localhost:8080`.

Common flags: `--secret-provider file --secret-dir ./secrets` for file-based secrets, `--policy-public-key <key> --policy-require-signature` for signed bundles.

### CI Mode

```bash
oag doctor --policy policy.yaml --json --verbose > doctor.json
oag test --policy policy.yaml --cases cases.yaml --json --verbose > policy-test.json
oag run --policy policy.yaml --log audit.jsonl
```

Bundle verification: `oag verify --bundle policy.bundle.json --public-key ./keys/policy-public.pem --json`

**Exit codes:** `0` = success, `1` = validation/execution failure.

**Artifacts:** `doctor.json` (config report), `policy-test.json` (case outcomes), `audit.jsonl` (audit trail).

### Sidecar / Container

Set `HTTP_PROXY` and `HTTPS_PROXY` on the agent container. Mount policy file and secrets directory into the OAG container.

```dockerfile
# Example Dockerfile
FROM eclipse-temurin:21-jre-alpine
COPY oag-app-all.jar /app/oag.jar
ENTRYPOINT ["java", "-jar", "/app/oag.jar"]
CMD ["run", "--policy", "/config/policy.yaml", "--log", "/logs/audit.jsonl"]
```

Or with the native binary:

```dockerfile
FROM alpine:3.20
COPY oag /usr/local/bin/oag
ENTRYPOINT ["oag"]
CMD ["run", "--policy", "/config/policy.yaml", "--log", "/logs/audit.jsonl"]
```

### Dry-Run Mode

Observe violations while still allowing traffic: `--dry-run`

### Hardened Mode

```bash
oag run --policy policy.yaml \
  --block-ip-literals \
  --block-private-resolved-ips \
  --enforce-redirect-policy \
  --connect-timeout-ms 5000 \
  --read-timeout-ms 30000
```

### OpenTelemetry Export

```bash
oag run --policy policy.yaml --otel-exporter otlp_http --otel-endpoint http://localhost:4318/v1/logs
```

Options: `--otel-headers`, `--otel-timeout-ms`, `--otel-service-name`. Use `--otel-exporter stdout` for local inspection.

### Policy Bundle Lifecycle

```bash
oag bundle --policy policy.yaml --out policy.bundle.json
oag bundle --policy policy.yaml --out policy.bundle.json --sign-key ./keys/policy-private.pem --key-id policy-root-1
oag verify --bundle policy.bundle.json --public-key ./keys/policy-public.pem
```

### CLI JSON Modes

`doctor --json`, `explain --json`, `test --json`, `hash --json`, `bundle --json`, `verify --json`, `help --json` (all support `--verbose`).

## Packaging

### Build

```bash
./gradlew assembleDist installDist shadowJar
```

**Artifacts:**
- `oag-app/build/libs/oag-app-1.0-SNAPSHOT-all.jar` — single-file runnable JAR (19 MB)
- `build/distributions/oag-1.0-SNAPSHOT.{zip,tar}` — distribution archives
- `build/install/oag/` — expanded layout with `bin/oag` (Unix) and `bin/oag.bat` (Windows)

### Native Binary (GraalVM)

Build an AOT-compiled native binary with GraalVM:

```bash
# Install GraalVM JDK 21+ (includes native-image)
# Then:
./gradlew shadowJar
native-image -jar oag-app/build/libs/oag-app-1.0-SNAPSHOT-all.jar -o oag
```

**Result:** A single ~58 MB executable. No JVM required at runtime.

Platform-specific notes:
- **Linux/macOS:** Works out of the box with GraalVM CE or Oracle GraalVM.
- **Windows:** Requires Visual Studio 2022 Build Tools. Use `-H:-CheckToolchain` if using a different VS version.

### CI Native Image Build (GitHub Actions)

```yaml
- uses: graalvm/setup-graalvm@v1
  with:
    java-version: '21'
    distribution: 'graalvm'
- run: ./gradlew shadowJar
- run: native-image -jar oag-app/build/libs/oag-app-1.0-SNAPSHOT-all.jar -o oag
- uses: actions/upload-artifact@v4
  with:
    name: oag-${{ runner.os }}
    path: oag
```

### Running from Distribution

```bash
# Native binary
./oag run --policy policy.yaml --port 8080 --log audit.jsonl

# Fat JAR
java -jar oag-app/build/libs/oag-app-1.0-SNAPSHOT-all.jar run --policy policy.yaml --port 8080 --log audit.jsonl

# Gradle distribution
build/install/oag/bin/oag run --policy policy.yaml --port 8080 --log audit.jsonl
```

### Config Directory

`--config-dir <dir>` provides convention-based defaults:
- Policy: `<dir>/policy.yaml`
- Audit log: `<dir>/logs/audit.jsonl`
- Secrets: `<dir>/secrets`

Explicit flags override these defaults. Bundles must be passed explicitly via `--policy` (no auto-detection).

## Performance

Measured with real upstream traffic (OpenAI, Anthropic, Brave Search APIs). Timing from audit event `phase_timings`.

### Request Latency

| Scenario | Total | OAG Overhead | Network I/O |
|---|---|---|---|
| Denied HTTP | 0.34-0.44 ms | 100% | — |
| Allowed HTTP | 19-79 ms | 1.2-1.5 ms | 94-98% |
| Denied CONNECT | 0.40-0.44 ms | 100% | — |
| Allowed CONNECT | varies | < 0.5 ms setup | tunnel lifetime |

### Phase Breakdown (allowed HTTP, warm path)

| Phase | Time |
|---|---|
| Policy evaluation | 0.08 ms |
| DNS resolution | < 0.01 ms (cached) |
| Secret materialization | 0.10-0.12 ms |
| Upstream connect | 9-67 ms (network) |
| Request relay | 0-0.58 ms |
| Response relay | 8-11 ms (network) |

**Key insight:** OAG overhead is < 2 ms per request. Denied requests complete in under 0.5 ms with zero network I/O. On allowed requests, 94-98% of total time is upstream network latency.

## Circuit Breaker

Per-host circuit breaker stops forwarding to consistently failing upstreams.

**States:** CLOSED → OPEN (after threshold failures) → HALF_OPEN (after reset timeout) → CLOSED (on success) or back to OPEN (on failure).

```bash
oag run --policy policy.yaml \
  --circuit-breaker-threshold 5 \
  --circuit-breaker-reset-ms 30000 \
  --circuit-breaker-half-open-probes 2
```

- `--circuit-breaker-threshold <n>`: Consecutive failures before opening. Default: 5.
- `--circuit-breaker-reset-ms <ms>`: Time before transitioning from OPEN to HALF_OPEN. Default: 30000.
- `--circuit-breaker-half-open-probes <n>`: Successful probes required in HALF_OPEN before closing. Default: 1.

Checked before all upstream connections (HTTP, CONNECT, MITM). Open circuit returns `503` with reason code `circuit_open`. State transitions emit `circuit_breaker` audit events.

## Graceful Shutdown

On `SIGTERM`/`SIGINT`: stop accepting connections → drain active connections → exit.

```bash
oag run --policy policy.yaml --drain-timeout-ms 10000
```

When admin server is enabled, `/healthz` returns `503 draining` during shutdown, allowing load balancers to stop routing traffic.

```yaml
# Kubernetes readiness probe
readinessProbe:
  httpGet:
    path: /healthz
    port: 9090
  periodSeconds: 5
  failureThreshold: 1
```

## Velocity Spike Detection

Detect abnormal request rate spikes per session:

```bash
oag run --policy policy.yaml --velocity-spike-threshold 3.0
```

- `--velocity-spike-threshold <n>`: Multiplier over baseline RPS before flagging. Set to `0` (default) to disable.

When the request rate exceeds the threshold relative to the session's baseline, requests are flagged in audit events. Requires `--session` to be set.

## Signed Header Verification

Require agents to cryptographically sign request headers:

```bash
oag run --policy policy.yaml \
  --require-signed-headers \
  --agent-signing-secret "shared-secret-value"
```

- `--require-signed-headers`: Reject requests without valid HMAC signatures.
- `--agent-signing-secret <secret>`: Shared secret used to verify HMAC-SHA256 signatures on request headers.

When enabled, agents must include a signature header computed over canonical request headers. Requests without a valid signature are denied.

## mTLS Client Authentication

Require clients to present a TLS client certificate:

```bash
oag run --policy policy.yaml \
  --mtls-ca-cert ./ca.pem \
  --mtls-keystore ./keystore.p12 \
  --mtls-keystore-password changeit
```

- `--mtls-ca-cert <path>`: CA certificate PEM file for verifying client certificates.
- `--mtls-keystore <path>`: PKCS12 keystore file containing the proxy's server certificate and key.
- `--mtls-keystore-password <password>`: Keystore password.

When configured, only clients presenting certificates signed by the specified CA are accepted. Client identity (CN/SAN) is recorded in audit events.

## Log Rotation

```bash
oag run --policy policy.yaml --log audit.jsonl \
  --log-max-size-mb 50 \
  --log-max-files 10 \
  --log-compress \
  --log-rotation-interval daily
```

- `--log-max-size-mb <n>`: Maximum file size before rotation. Default: 0 (disabled).
- `--log-max-files <n>`: Maximum rotated files to retain. Default: 5.
- `--log-compress`: Gzip-compress rotated files.
- `--log-rotation-interval <interval>`: Time-based rotation (`daily`, `hourly`). Used alongside or instead of size-based rotation.

Rotated files named `<logfile>.1`, `<logfile>.2`, etc. (`.1` = most recent). When `--log-rotation-interval` is set to `daily` or `hourly`, rotated files are named `<logfile>.<period>` where period is formatted as `yyyy-MM-dd` for daily or `yyyy-MM-dd-HH` for hourly (e.g., `audit.jsonl.2026-03-26` or `audit.jsonl.2026-03-26-14`). Only applies to file logging.

## Integrity Checking

Periodic runtime integrity verification:

```bash
oag run --policy policy.yaml --integrity-check-interval-s 300
```

- `--integrity-check-interval-s <n>`: Interval in seconds between integrity checks. Default: 0 (disabled).

Checks:
- **Policy hash:** Constant-time comparison against expected value.
- **Config fingerprint:** SHA-256 of canonical config fields.

Emits `integrity_check` audit events with status (`pass` or `drift_detected`).

## Policy Reload at Runtime

OAG supports reloading the policy at runtime without restarting the proxy. Four triggers are available:

### Admin Endpoint

POST `/admin/reload` triggers an immediate policy reload:

```bash
curl -X POST http://localhost:9090/admin/reload
```

Response (success):

```json
{"ok":true,"changed":true,"policy_hash":"<new_hash>"}
```

Response (failure):

```json
{"ok":false,"error":"<error_message>"}
```

Response (cooldown active — HTTP 429):

```json
{"ok":false,"error":"<error_message>","retry_after_s":<seconds>}
```

The cooldown shape is returned when a reload is requested before `--admin-reload-cooldown-ms` has elapsed since the last reload. `retry_after_s` indicates how many seconds to wait before retrying.

GET requests to `/admin/reload` return 405.

### SIGHUP Signal (Unix)

On Unix systems, sending SIGHUP to the OAG process triggers a policy reload:

```bash
kill -HUP <pid>
```

### File Watcher

The `--watch` flag uses file system notifications (separate from signal/admin reload). See [configuration.md](configuration.md#policy-hot-reload) for watcher details.

### Remote Policy Fetching

When `--policy-url` is configured, OAG periodically fetches the policy from a remote URL and triggers a reload when the content changes. See [Remote Policy Fetching](#remote-policy-fetching) for full details.

### Behavior

On reload, OAG:
1. Re-reads and validates the policy file
2. If the policy hash changed, reconfigures rate limiters for updated rules
3. Emits a `policy_reload` audit event with `trigger` field (`admin_endpoint`, `signal`, `file_watcher`, or `policy_fetch`)

All four mechanisms can coexist.

## Remote Policy Fetching

OAG can periodically fetch policies from a remote HTTP(S) URL:

```bash
oag run --policy /tmp/cached-policy.yaml --policy-url https://config.example.com/policy.yaml \
  --policy-fetch-interval-s 300
```

### Flags

- `--policy-url <url>`: Remote URL to fetch the policy from. The fetched content is written to the `--policy` path.
- `--policy-fetch-interval-s <n>`: Fetch interval in seconds (default 60).

### Behavior

- On startup, the local `--policy` path is loaded as usual. The fetcher runs in the background.
- Each fetch compares a SHA-256 hash of the downloaded content against the last known hash.
- When the content changes, the file at `--policy` is overwritten and a policy reload is triggered.
- Fetch events are logged as `policy_fetch` audit events with `source_url`, `success`, `changed`, and `content_hash`.
- If `--watch` is also enabled, the file watcher will additionally trigger on the fetcher's file writes.

## Admin Server

Enable with `--admin-port <port>`:

```bash
oag run --policy policy.yaml --admin-port 9090 --admin-token mysecret
```

- `--admin-port <n>`: Port for the admin HTTP server.
- `--admin-allowed-ips <list>`: Comma-separated IP addresses or CIDR ranges. Non-listed IPs receive 403.
- `--admin-token <token>`: Bearer token required for admin requests. Note: `/healthz` is exempt — health checks bypass token authentication regardless of this setting.
- `--admin-reload-cooldown-ms <ms>`: Minimum interval between reloads. Default: 5000.

See [observability.md](observability.md#admin-server) for endpoints and metrics.

## Webhooks

```bash
oag run --policy policy.yaml \
  --webhook-url https://hooks.example.com/oag \
  --webhook-events circuit_open,reload_failed \
  --webhook-timeout-ms 5000 \
  --webhook-signing-secret mysecret
```

- `--webhook-url <url>`: Destination for webhook notifications.
- `--webhook-events <list>`: Comma-separated event types to send. Valid values:
  - `circuit_open` — Circuit breaker opened for a host
  - `reload_failed` — Policy reload attempt failed
  - `injection_detected` — Prompt injection detected in request
  - `credential_detected` — Outbound credentials detected in request body
  - `integrity_drift` — Policy hash or config fingerprint drifted from initial state
  - `admin_denied` — Admin endpoint access denied
- `--webhook-timeout-ms <ms>`: HTTP timeout for webhook delivery. Default: 5000.
- `--webhook-signing-secret <secret>`: HMAC-SHA256 signing secret. Adds `X-OAG-Signature: sha256=<hex>` header.

Failed webhook deliveries are retried up to 3 times with exponential backoff (500ms base, 5s max). Events that exhaust all retries are dropped.

## Connection Pooling

```bash
oag run --policy policy.yaml --pool-max-idle 8 --pool-idle-timeout-ms 60000
```

- `--pool-max-idle <n>`: Maximum idle connections per upstream host:port. Default: 0 (disabled).
- `--pool-idle-timeout-ms <ms>`: Idle timeout before eviction. Default: 60000.

Only applies to HTTP forward proxy requests. CONNECT tunnels and MITM connections are not pooled.

## Smoke Test

```powershell
./scripts/smoke-test.ps1
./scripts/smoke-test.ps1 -TestSecrets -SecretProvider env
./scripts/smoke-test.ps1 -TestSecrets -SecretProvider file -SecretDir .\tmp\secrets
```

Uses temporary local policy and HTTP server. Expected: `ALLOW_STATUS=200`, `DENY_STATUS=403`.

## Ops Validation

Production-style validation: throughput baseline, stress behavior, fault handling.

```powershell
./scripts/ops-bench.ps1 -Requests 300 -Concurrency 12
./scripts/ops-stress.ps1 -Requests 2000 -Concurrency 48 -PayloadBytes 0
./scripts/ops-faults.ps1
./scripts/ops-run.ps1 -BenchRequests 300 -BenchConcurrency 12 -StressRequests 2000 -StressConcurrency 48
```

All scripts except `smoke-test.ps1` support `-Json` for CI output. `ops-run.ps1` orchestrates all three and produces combined JSON summary. Use `-GradleArgs` for custom flags (file provider, bundles, etc.).

**Prerequisites:** Python (local upstream server), `curl.exe` (fault injection).

### Bench Script (`ops-bench.ps1`)

Inputs: `-Requests`, `-Concurrency`, `-ProxyPort`, `-UpstreamPort`, `-GradleArgs`, `-WarmupRequests`, `-Output`, `-VerifyAudit`, `-StrictAudit`, `-AuditMinRate`, `-Seed`.
Outputs: total time, errors, RPS, P50/P95/P99 latency.

### Stress Script (`ops-stress.ps1`)

Same inputs plus `-PayloadBytes` (0=GET, >0=POST). Geared for higher concurrency.

### Fault Injection (`ops-faults.ps1`)

Checks: bad policy validation, secret materialization failure (403), upstream connection failure (502). Optional `-BundleVerify`.

### Interpretation

- Errors > 0: inspect `audit.jsonl` for dominant `reason_code`.
- Latency spikes: lower concurrency to isolate CPU vs I/O.
- Repeated faults: `oag doctor --json`.

All scripts auto-cleanup. If a process is left over, terminate the Gradle Java process.

## Troubleshooting

**Proxy not receiving traffic** — Ensure agent uses `HTTP_PROXY`/`HTTPS_PROXY`. Confirm OAG is listening on configured port.

**Unexpected denies** — Check policy host/method/path. For HTTPS traffic, ensure `CONNECT` is in the methods list and `paths` is omitted (CONNECT requests have no path). Use `oag explain` to test specific requests.

**HTTPS tunnel hangs** — Ensure `CONNECT` is allowed for the target host. CONNECT tunnels need the method explicitly listed. Omit `paths` from rules that allow CONNECT.

**Secret injection failures** — Ensure placeholders are present (`OAG_PLACEHOLDER_<ID>`). Ensure `OAG_SECRET_<ID>` env var exists (or `<id>.secret` file for file provider). Empty secret files are treated as missing.

**Bundle verification failures** — Ensure `--policy-require-signature` is only used with signed bundles. Confirm `--policy-public-key` points to valid Ed25519 X.509 public key. Recreate with `oag bundle`, verify with `oag verify`.

**Invalid request errors** — OAG rejects malformed headers, invalid tokens, conflicting framing. `Transfer-Encoding` requests are rejected.

**Read timeout for LLM APIs** — Default read timeout is 30 seconds, which may be too short for streaming LLM responses. Use `--read-timeout-ms 120000` for 2-minute timeout.

**Audit log confusion** — Use `agent_id`/`session_id` to correlate events. `reason_code` identifies deny rationale.

**Port already in use** — Another process is bound to the port. On Linux/macOS: `lsof -i :<port>`. On Windows: `netstat -ano | findstr :<port>`, then `taskkill /F /PID <pid>`.

## Agent Integration Example

Wire any HTTP-proxy-capable agent to OAG:

1. Create policy file with allow/deny rules and secret IDs. Include `CONNECT` in methods for HTTPS hosts.
2. Set secrets: `OAG_SECRET_<ID>=<value>` (env) or `<id>.secret` files (file provider).
3. Start OAG: `oag run --policy policy.yaml --port 8080 --log audit.jsonl`
4. Configure agent: `HTTP_PROXY=http://127.0.0.1:8080`, `HTTPS_PROXY=http://127.0.0.1:8080`
5. Agents use placeholders in headers: `Authorization: Bearer OAG_PLACEHOLDER_OPENAI_KEY`
6. Verify: denied requests return 403; allowed requests are forwarded. Check `audit.jsonl` for `decision.action`, `decision.reason_code`, `secrets.injected`.

**Notes:** Secret injection is headers only. HTTPS is tunneled via CONNECT (opaque unless TLS interception enabled). Body limits enforced by Content-Length only.

## Complete Flag Reference

See [cli.md](cli.md) for the full list of all commands and flags.
