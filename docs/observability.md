# Observability

OAG emits structured JSONL audit logs, Prometheus metrics, and optional OpenTelemetry exports. Redaction-safe defaults: no secret values or raw credentials in logs.

## Audit Events

### Event Types

| Type | Trigger | Key Fields |
|---|---|---|
| `startup` | Proxy starts | `config.*` (all runtime flags, paths, timeouts) |
| `request` | Every HTTP request | `request.*`, `response.*`, `decision.*`, `secrets.*`, `content_inspection.*` |
| `tool` | MCP tool call | `tool.{name,parameter_keys,duration_ms,error_code}` |
| `policy_reload` | Reload attempt | `previous_policy_hash`, `new_policy_hash`, `changed`, `success`, `trigger` |
| `circuit_breaker` | CB state transition | `host`, `previous_state`, `new_state` |
| `policy_fetch` | Remote policy fetched | `source_url`, `success`, `changed`, `content_hash` |
| `admin_access` | Admin endpoint accessed | `endpoint`, `source_ip`, `allowed` |
| `integrity_check` | Periodic integrity check | `status` (pass/drift_detected), policy hash match, config fingerprint match |

### Request Event Fields

**Core:** `timestamp`, `schema_version`, `oag_version`, `policy_hash`, `agent_id`/`session_id`, `request.{host,port,scheme,method,path,bytes_out}`, `response.{bytes_in,status}`, `decision.{action,rule_id,reason_code}`, `secrets.{injection_attempted,injected,secret_ids,secret_versions}`, `errors`.

**Optional:** `trace.{trace_id,span_id,trace_flags}` (from W3C `traceparent`), `redirect_chain`, `content_inspection.*`, `request_id`, `retry_count`, `tags`, `header_rewrites`, `request.resolved_ips`, `web_socket_session.*`, `agent_profile`, `token_usage.{prompt_tokens,completion_tokens,total_tokens}` (LLM token usage extracted from response body, present when OAG detects token usage fields in JSON API responses), `dry_run_override` (boolean, present when the request was allowed despite a deny decision because `--dry-run` is enabled), `phase_timings.{policy_evaluation_ms,dns_resolution_ms,upstream_connect_ms,request_relay_ms,response_relay_ms,secret_materialization_ms,total_ms}` (per-phase execution times in milliseconds, only non-zero phases are included), `response_rewrites` (list of response body/header modifications applied; each entry has `action` (redact/remove_header/set_header), and optional `pattern`, `header`, `redaction_count`), `structured_payload.{protocol,method,operation_name,operation_type}` (detected structured API payload information; `protocol` is jsonrpc/graphql).

### Tool Event Fields

`tool.{name,parameter_keys,parameters,response_bytes,duration_ms,error_code}`. Parameter values redacted by default.

### JSONL Examples

Request event (allow):
```json
{"timestamp":"2026-02-21T12:00:00Z","schema_version":"3","oag_version":"0.1.0","policy_hash":"abc123","agent_id":"agent-1","session_id":"session-1","request":{"host":"api.openai.com","port":443,"scheme":"https","method":"POST","path":"/v1/chat/completions","bytes_out":120},"response":{"bytes_in":2450,"status":200},"decision":{"action":"allow","reason_code":"allowed_by_rule","rule_id":"openai-allow"},"secrets":{"injected":true,"injection_attempted":true,"secret_ids":["OPENAI_API_KEY"]},"errors":[]}
```

Tool event:
```json
{"timestamp":"2026-02-21T12:00:01Z","schema_version":"3","event_type":"tool","oag_version":"0.1.0","policy_hash":"abc123","agent_id":"agent-1","session_id":"session-1","tool":{"name":"web.search","parameter_keys":["api_key","query"],"parameters":{"api_key":"[REDACTED]","query":"[REDACTED]"},"duration_ms":28,"response_bytes":512}}
```

Policy reload:
```json
{"timestamp":"2026-02-21T12:00:02Z","schema_version":"3","event_type":"policy_reload","oag_version":"0.1.0","agent_id":"agent-1","session_id":"session-1","changed":true,"previous_policy_hash":"abc123","new_policy_hash":"def456","success":true,"trigger":"file_watcher"}
```

Circuit breaker:
```json
{"timestamp":"2026-02-21T12:00:03Z","schema_version":"3","event_type":"circuit_breaker","oag_version":"0.1.0","agent_id":"agent-1","session_id":"session-1","host":"api.failing.com","previous_state":"closed","new_state":"open"}
```

## Prometheus Metrics

| Name | Type | Labels | Description |
|---|---|---|---|
| `oag_requests_total` | counter | `action`, `reason_code`, `rule_id`, `tags` | Total proxy decisions |
| `oag_rate_limited_total` | counter | — | Rate-limited requests |
| `oag_dry_run_override_total` | counter | — | DENY decisions overridden by dry-run mode |
| `oag_request_duration_ms` | histogram | `le` | Request duration (buckets: 5,10,25,50,100,250,500,1000,5000,30000ms) |
| `oag_phase_duration_ms` | histogram | `phase` | Per-phase request latency (buckets: 1,2,5,10,25,50,100,250,500,1000ms) |
| `oag_active_connections` | gauge | — | Current active connections |
| `oag_pool_hits_total` | counter | — | Connection pool hits |
| `oag_pool_misses_total` | counter | — | Connection pool misses |
| `oag_pool_evictions_total` | counter | — | Connection pool evictions |
| `oag_audit_dropped_total` | counter | — | Audit events dropped due to full queue |

Naming: `oag_` prefix, `snake_case`, units in suffix (`_ms`), counters end `_total`.

### Performance Profiling

`RequestProfiler` tracks 7 per-request phase timings: `policy_evaluation`, `dns_resolution`, `upstream_connect`, `request_relay`, `response_relay`, `secret_materialization`, `total_ms`.

## Admin Server

Optional HTTP server on a separate port (`--admin-port <port>`):

| Endpoint | Method | Description |
|---|---|---|
| `/healthz` | GET | 200 OK or 503 draining (during shutdown) |
| `/metrics` | GET | Prometheus text exposition format |
| `/admin/reload` | POST | Trigger policy reload |
| `/admin/pool` | GET | Connection pool statistics |
| `/admin/policy` | GET | Current policy hash and rule counts |
| `/admin/audit` | GET | Decision counts since startup |
| `/admin/tasks` | GET | Running background task snapshots |

IP restriction: `--admin-allowed-ips 10.0.0.1,192.168.1.0/24`. Non-listed IPs receive 403. Access logged as `admin_access` events.

Runs on daemon threads. All endpoints including `/healthz` emit `admin_access` audit events. Plain HTTP — bind to `127.0.0.1` or use a sidecar in production.

Prometheus scrape config:
```yaml
scrape_configs:
  - job_name: oag
    static_configs:
      - targets: ["localhost:9090"]
    metrics_path: /metrics
```

## OpenTelemetry Export

```bash
oag run --policy policy.yaml --otel-exporter otlp_http --otel-endpoint http://localhost:4318/v1/logs
```

Exporters: `none` (default), `otlp_http`, `otlp_grpc`, `stdout`. Options: `--otel-headers`, `--otel-timeout-ms`, `--otel-service-name`. Audit events mapped to OTel log records with HTTP semantic attributes.

### Distributed Tracing

When OTel is configured, OAG creates a server-kind span for each proxied request with `http.request.method`, `server.address`, and `url.path` attributes. OAG also injects a W3C `traceparent` header into upstream requests, enabling trace correlation across the agent, OAG, and backend services. If the incoming request already carries a `traceparent` header, OAG links its span to the parent trace context.

## Log Rotation

```bash
oag run --log audit.jsonl --log-max-size-mb 50 --log-max-files 10 --log-compress
```

Files named `<logfile>.1`, `.2`, etc. (`.1` = most recent). Gzip compression with `--log-compress`. Only applies to file logging.

## Webhook Notifications

```bash
oag run --webhook-url https://hooks.example.com/oag \
  --webhook-events circuit_open,reload_failed \
  --webhook-signing-secret mysecret
```

Events: `circuit_open`, `reload_failed`, `injection_detected`, `credential_detected`, `integrity_drift`, `admin_denied`. JSON payload with `eventType`, `timestamp`, `data`. Optional HMAC-SHA256 signature header (`x-oag-signature: sha256=<hex>`). Best-effort, non-blocking delivery.

## Integrity Checking

Periodic runtime integrity verification:

- **Policy hash:** Constant-time comparison against expected value set at startup (updated on reload).
- **Config fingerprint:** SHA-256 of 33+ canonical config fields (listen host/port, timeouts, TLS, secrets, policy, logging, admin, circuit breaker, connection pool, webhooks, OTel).

Configure: `--integrity-check-interval-s <n>`. Emits `integrity_check` audit events with status (`pass` or `drift_detected`).

## Redaction & Searchability

**Redaction:** Parameter values redacted by default. Secret IDs logged without values.

**Correlation fields:** `policy_hash`, `agent_id`/`session_id`, `trace.trace_id`/`trace.span_id`, `decision.action`/`decision.reason_code`.

**Common filters:** `decision.action == deny` (all denies), `reason_code == no_match_default_deny` (policy misses), `reason_code == invalid_request` (parsing errors).

**Best practice:** Set `--agent` and `--session` for each run. Filter by `reason_code` to group failures.
