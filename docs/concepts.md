# Concepts

## What OAG Does

OAG is a portable egress policy engine, secret materializer, and audit recorder for AI agents. It runs as an HTTP/HTTPS forward proxy between agents and the internet.

- **Enforce outbound network policy** using deterministic rules (deny > allow).
- **Keep secrets out of the agent process** — materialize them only for permitted requests.
- **Produce structured audit evidence** for every outbound request and tool call.

OAG is not a sandbox and does not own the compute plane.

## Architecture

### Components

| Component | Responsibility |
|---|---|
| **Policy Engine** | Parse/validate policies (YAML/JSON), evaluate requests deterministically, produce decisions with reason codes. Supports bundles with Ed25519 signatures. |
| **Egress Proxy** | HTTP/HTTPS forward proxy with CONNECT, TLS MITM, WebSocket relay, connection pooling, circuit breaker. |
| **Secret Materializer** | Detect placeholder tokens in headers, inject real secrets for allowed destinations, emit redaction-safe events. |
| **Content Inspector** | Scan request/response bodies for injection patterns, sensitive data, credentials, path traversal. Heuristic + optional ML scoring. |
| **Audit Recorder** | Emit JSONL events with stable schema for every request. Optionally export to OpenTelemetry. |

### Data Flow

```
Agent ──HTTP(S)──> Proxy ──> Policy Engine
                     │──> Content Inspector
                     │──> Secret Materializer
                     │──> Upstream
                     └──> Audit Recorder
```

### Extension Points

OAG provides SDK types for external agent frameworks to emit tool call audit events. These are not used by OAG's proxy runtime.

| Extension | Types | Purpose |
|---|---|---|
| Tool call auditing | `ToolAuditAdapter`, `AuditToolEvent`, `ToolCallInput` | Record tool calls with parameter keys (values redacted), response size, duration, error codes. Import `oag-audit` to use. |

### Decision Path

1. Request enters proxy — parse target (host, method, path, scheme, port).
2. Policy engine evaluates: deny rules checked first, then allow rules.
3. Content inspection scans request body (injection, credentials, sensitive data, path analysis).
4. If allowed, placeholder secrets are materialized for that request only.
5. Secret scopes further restrict materialization to specific destinations.
6. Header rewrites applied. Request forwarded upstream.
7. Response scanned (fixed-length and streaming).
8. Redirects re-evaluated as new requests (when enabled).
9. Audit event emitted with decision, timing, and metadata.

**Failure modes:** Policy error → deny + log. Secret error → deny + log. Network error → log with partial data.

## Default Deny

When `defaults.action` is omitted or set to `deny`, unmatched requests are blocked. Deny rules always take priority over allow rules when both match the same request. This is the recommended and default security posture.

Setting `defaults.action: allow` is supported for audit-only deployments but disables default-deny — unmatched requests are forwarded. The `oag lint` command warns when this is configured (`UNSAFE_DEFAULT_ALLOW`).

## Secret Materialization

Agents never hold raw credentials. Instead, they use placeholder tokens in request headers:

```
Authorization: Bearer OAG_PLACEHOLDER_OPENAI_KEY
```

When an allowed request matches a rule with `secrets: [OPENAI_KEY]`, OAG replaces the placeholder with the real secret value from the configured provider (environment variable or file). Secret scopes further restrict which hosts, methods, and paths may trigger materialization.

## Module Tree

10 Gradle modules in dependency layers (each layer depends only on layers above):

| Layer | Module | Responsibility |
|---|---|---|
| 0 — Foundation | `oag-core` | Shared types, constants, utilities, HTTP parsing |
| 1 — Domain logic | `oag-policy` | Policy model, evaluation, validation, distribution |
| 1 — Domain logic | `oag-audit` | Audit event model, JSONL writer, external sink interface |
| 1 — Domain logic | `oag-secrets` | Secret providers (env, file, OAuth2), materialization |
| 2 — Detection | `oag-inspection` | Detector SPI, injection patterns, credential/data classification |
| 2 — Observability | `oag-telemetry` | OTel tracer, Prometheus metrics, request profiler |
| 3 — Enforcement | `oag-enforcement` | Circuit breaker, rate limiter, budget trackers, session tracking |
| 4 — Composition | `oag-pipeline` | Phase interface, Pipeline class, up to 28 phases (7 conditional), response relay |
| 5 — Runtime | `oag-proxy` | TCP server, admin server, TLS/MITM, WebSocket, handler factories |
| 6 — Entry point | `oag-app` | CLI parser, commands, config builder, startup |

- Dependency direction: DAG only, no cycles. Pure logic at leaves, side effects at root.
- `policy`, `secrets`, `audit` are pure — no dependency on `proxy` or `pipeline`.
- `pipeline` composes policy decisions into ordered phases; `proxy` handles I/O and protocol.

## Threat Model

| Threat | Mitigation |
|---|---|
| SSRF — agent calls internal/metadata services | Default-deny, redirect re-evaluation, IP literal blocking, DNS hardening |
| Secret exfiltration — secrets leak via tools/logs | Request-time-only materialization, redaction-safe audit |
| Data exfiltration — sensitive data sent outbound | Content inspection, URL/DNS entropy guards, data budgets, credential detection |
| Prompt injection — responses manipulate agent | Response scanning, streaming detection, heuristic/ML scoring |
| Open proxy abuse — agent used as relay | Policy enforcement, rate limiting, circuit breaker |

**Residual risks:** Application-layer misuse of allowed destinations, upstream service secret exposure, non-HTTP egress outside OAG scope, `defaults.action: allow` configuration disabling default-deny.

## Design Principles

| Principle | Rule |
|---|---|
| Dependency direction | DAG only, no cycles. Pure logic at leaves, side effects at root. |
| Fail closed | Deny on any error. Restrictive overrides permissive. Default-deny when `defaults.action` is omitted (configurable). |
| Pipeline phases | Typed outcomes (continue/short-circuit) within phase logic. `orDenyDryRunnable()` is the primary method used by gate phases — it converts a `PhaseOutcome.Deny` into a throw to short-circuit the pipeline, but in dry-run mode it logs the denial and continues instead of throwing. `orDeny()` is the lower-level variant that always throws regardless of dry-run. Exceptions are the transport mechanism for short-circuit flow, not arbitrary error handling. |
| Schema stability | Enums/reason codes append-only. Deterministic hashing. |
| Semantic packaging | Group by concern. Each package owns one domain concept. |
| Boundary conversion | Domain types internally; wire format at serialization edges. |

## References

- [RFC9110] HTTP Semantics — https://datatracker.ietf.org/doc/html/rfc9110
- [RFC9112] HTTP/1.1 — https://datatracker.ietf.org/doc/html/rfc9112
- [IANA-SP] Special-Purpose Addresses — https://www.iana.org/assignments/special-purpose-addresses
- [OWASP-SSRF] SSRF Prevention — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- [OTEL-LOGS] OTel Logs Data Model — https://opentelemetry.io/docs/specs/otel/logs/data-model/
- [OTEL-HTTP] OTel HTTP Conventions — https://opentelemetry.io/docs/specs/semconv/http/
- [W3C-TRACE] Trace Context — https://www.w3.org/TR/trace-context/
