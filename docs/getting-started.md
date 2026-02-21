# Getting Started

This guide walks you through installing OAG, writing your first policy, and verifying enforcement end-to-end.

## Prerequisites

- A terminal with `bash` or PowerShell
- `curl` (for testing)

JDK 21+ only needed if building from source.

## Install

Download the binary for your platform from [Releases](https://github.com/mustafadakhel/oag/releases) and place it on your PATH:

```bash
# Linux / macOS
chmod +x oag
sudo mv oag /usr/local/bin/

# Windows — add the directory containing oag.exe to your PATH
```

Verify:

```bash
oag help
```

A fat JAR (`oag-app-1.0-SNAPSHOT-all.jar`) is also available on the Releases page for platforms without a native binary. Run with `java -jar oag-app-1.0-SNAPSHOT-all.jar help` (requires JDK 21+).

### Build from Source

```bash
git clone https://github.com/mustafadakhel/oag.git
cd oag
./gradlew shadowJar
```

For development, run directly without building a JAR:

```bash
./gradlew :oag-app:run --args="help"
```

## Write a Policy

Create `policy.yaml`:

```yaml
version: 1

defaults:
  action: deny
  max_body_bytes: 1048576

allow:
  - id: openai_api
    host: api.openai.com
    methods: [CONNECT, POST, GET]
    paths: [/v1/*]
    secrets: [OPENAI_KEY]

  - id: anthropic_api
    host: api.anthropic.com
    methods: [CONNECT, POST]
    paths: [/v1/*]
    secrets: [ANTHROPIC_KEY]

deny:
  - id: cloud_metadata
    host: 169.254.169.254
```

This policy allows POST/GET requests to OpenAI and POST requests to Anthropic, blocks cloud metadata access, and denies everything else by default.

**HTTPS traffic**: Agents use HTTP CONNECT tunneling for HTTPS destinations. Include `CONNECT` in the `methods` list for any host the agent will access over HTTPS. Omit `paths` when allowing CONNECT, since tunnel requests have no path.

See [configuration.md](configuration.md) for the full policy schema.

## Provide Secrets

OAG materializes secrets at request time so agents never see raw credentials.

**Environment variables** (default provider):

```bash
export OAG_SECRET_OPENAI_KEY="sk-your-key-here"
export OAG_SECRET_ANTHROPIC_KEY="sk-ant-your-key-here"
```

**File provider** (alternative):

```bash
mkdir secrets
echo -n "sk-your-key-here" > secrets/OPENAI_KEY.secret
echo -n "sk-ant-your-key-here" > secrets/ANTHROPIC_KEY.secret
```

Agents use placeholders in headers — OAG swaps them for real secrets on allowed requests:

```
Authorization: Bearer OAG_PLACEHOLDER_OPENAI_KEY
```

## Start OAG

```bash
oag run --policy policy.yaml --port 8080 --log audit.jsonl
```

With verbose logging to stderr:

```bash
oag run --policy policy.yaml --port 8080 --log audit.jsonl --verbose
```

File provider variant:

```bash
oag run --policy policy.yaml --port 8080 --log audit.jsonl --secret-provider file --secret-dir ./secrets
```

During development via Gradle:

```bash
./gradlew :oag-app:run --args="run --policy policy.yaml --port 8080 --log audit.jsonl"
```

## Verify with `oag explain`

Before running an agent, verify your policy evaluates as expected:

```bash
oag explain --policy policy.yaml --request "POST https://api.openai.com/v1/chat/completions"
```

Expected output:

```
action=allow reason=allowed_by_rule rule=openai_api
```

Try a denied request:

```bash
oag explain --policy policy.yaml --request "GET https://evil.com/exfil"
```

Expected output:

```
action=deny reason=no_match_default_deny rule=-
```

Use `--json` for machine-readable output:

```bash
oag explain --policy policy.yaml --request "POST https://api.openai.com/v1/chat/completions" --json
```

## Validate Configuration

Run the doctor command to check your policy and runtime config:

```bash
oag doctor --policy policy.yaml --json --verbose
```

## Point Your Agent at OAG

Configure any HTTP-proxy-capable agent:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

The agent sends requests through OAG. Denied requests return `403 Forbidden`. Allowed requests are forwarded upstream with secrets injected.

### Quick Test with curl

```bash
# Allowed HTTP request (expect upstream response)
curl -x http://127.0.0.1:8080 http://api.openai.com/v1/models

# Denied request (expect 403)
curl -x http://127.0.0.1:8080 http://evil.com/

# Allowed HTTPS via CONNECT tunnel
curl -x http://127.0.0.1:8080 https://api.openai.com/v1/models

# Denied HTTPS tunnel (expect 403)
curl -x http://127.0.0.1:8080 https://www.google.com/
```

## Check the Audit Log

Every request produces a JSONL audit event in `audit.jsonl`:

```json
{
  "timestamp": "2026-02-23T12:00:00Z",
  "decision": {"action": "allow", "reason_code": "allowed_by_rule", "rule_id": "openai_api"},
  "request": {"host": "api.openai.com", "port": 443, "scheme": "https", "method": "POST", "path": "/v1/chat/completions", "bytes_out": 512},
  "secrets": {"injection_attempted": true, "injected": true, "secret_ids": ["OPENAI_KEY"], "secret_versions": {}},
  "phase_timings": {"policy_evaluation_ms": 0.08, "total_ms": 19.72}
}
```

*Example abbreviated. Actual audit events include additional fields: `schema_version`, `event_type`, `oag_version`, `policy_hash`, `agent_id`, `session_id`, `redirect_chain`, `errors`, and others. Fields with null values are included in the output. See [Observability](observability.md) for the full schema.*

Filter for denies:

```bash
grep '"action":"deny"' audit.jsonl
```

See [observability.md](observability.md) for the full event schema and metrics.

## Performance

Measured on real network traffic (not benchmarks):

| Scenario | Total Time | OAG Overhead |
|---|---|---|
| Denied request | 0.34-0.44 ms | 100% (no network I/O) |
| Allowed HTTP request | 19-79 ms | 1.2-1.5 ms (rest is upstream) |
| CONNECT tunnel | varies | < 0.5 ms setup |
| Policy evaluation | — | 0.08 ms |
| Secret materialization | — | 0.10-0.12 ms |

OAG adds 1-2 ms of overhead to allowed requests. Denied requests complete in under 0.5 ms. On allowed requests, 94-98% of total time is upstream network I/O.

## Common Flags

| Flag | Description | Default |
|---|---|---|
| `--policy <path>` | Policy file path | required |
| `--port <n>` | Listen port | 8080 |
| `--log <path>` | Audit log file path | stdout |
| `--verbose` | Debug output to stderr | off |
| `--dry-run` | Log violations without blocking | off |
| `--watch` | Hot-reload policy on file change | off |
| `--read-timeout-ms <ms>` | Upstream read timeout | 30000 |
| `--connect-timeout-ms <ms>` | Upstream connect timeout | 5000 |
| `--secret-provider <type>` | Secret backend (`env`, `file`, or `oauth2`) | env |
| `--admin-port <n>` | Admin server port | disabled |

See [cli.md](cli.md) for the full flag reference.

## Next Steps

- [Concepts](concepts.md) — how OAG works, architecture, threat model
- [Configuration Reference](configuration.md) — full policy schema, rule fields, bundles, linting
- [CLI Reference](cli.md) — all commands, flags, JSON output schemas
- [Security](security.md) — content inspection, injection detection, exfiltration guards
- [Observability](observability.md) — audit events, Prometheus metrics, OpenTelemetry
- [Operations](operations.md) — deployment, packaging, resilience, testing
- [Policy Examples](examples/policy-examples.md) — ready-to-use policy recipes
