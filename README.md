# Open Agent Guard (OAG)

Portable runtime policy and audit layer for AI agents. OAG runs as an HTTP/HTTPS forward proxy between agents and the services they call — enforcing security policies, inspecting content, materializing secrets, and recording every decision.

It is not a sandbox and does not own the compute plane.

## Features

**Policy enforcement**
- Deterministic policy evaluation (deny rules checked before allow rules).
- Host, method, path, IP range, header, query, and structured payload matching.
- Agent profiles with per-agent rate limits, body size caps, and rule allowlists.
- Custom reason codes, per-rule error responses, and policy tags.

**Content inspection**
- Prompt injection detection with 6 built-in pattern families and heuristic scoring.
- Optional ONNX-based ML classifier for injection detection.
- Outbound credential detection (AWS keys, GitHub PATs, JWTs, private keys, Slack tokens, API keys, bearer tokens).
- Sensitive data classification (PII, financial, credentials) with configurable categories.
- URL/DNS exfiltration guards with Shannon entropy analysis.
- Path traversal and double-encoding detection.
- Plugin SPI for custom detectors.

**Secrets**
- Placeholder-based secret injection (`OAG_PLACEHOLDER_` headers, Bearer support).
- Secret scopes restricting which secrets apply to which hosts/methods/paths.
- Three providers: environment variables, files (with symlink/traversal protection), and OAuth2 client credentials (with token caching and automatic refresh).

**Proxy**
- HTTP/HTTPS forward proxy with CONNECT tunnel support.
- TLS interception (MITM) with ephemeral CA and per-host certificate generation.
- WebSocket frame relay with content inspection.
- Connection pooling, circuit breakers, and rate limiting (token bucket).
- Per-session data and token budget tracking.
- Redirect chain validation with policy re-evaluation per hop.

**Audit and observability**
- Structured audit logging (JSONL) with 8 event types and 32 reason codes.
- Rotating log files (size-based and time-based) with optional GZIP compression.
- OpenTelemetry integration: audit log export and distributed tracing with W3C `traceparent` propagation.
- 10 Prometheus metrics (counters, gauges, histograms).
- 7 admin API endpoints (health, metrics, reload, pool, policy, audit, tasks).
- Webhook notifications for 6 event types with HMAC signing and retry.

**CLI**
- 11 commands: run, doctor, explain, test, hash, bundle, verify, lint, simulate, diff, help.
- 77 configuration flags with JSON output mode for CI integration.
- Policy bundles with optional Ed25519 signatures.

## Dependencies

| Category | Libraries | Why |
|----------|-----------|-----|
| Serialization | kotlinx.serialization + kotaml (YAML) | Policy YAML parsing, audit JSONL output |
| Cryptography | BouncyCastle (bcprov, bcpkix) | Ed25519 bundle signatures, HMAC, TLS CA generation |
| Observability | OpenTelemetry SDK + exporters | Audit log export and distributed tracing via OTLP |
| Async | kotlinx-coroutines-core | Webhook delivery, background policy fetching, WebSocket relay |
| ML (optional) | ONNX Runtime, DJL | Optional ML-based injection classification (compileOnly) |

HTTP parsing, connection pooling, and the CLI parser are hand-rolled to avoid
pulling in a full web framework for what is fundamentally a TCP proxy.

## Compatibility

- Kotlin: 2.2.20 (JVM)
- JDK: 21 (toolchain)

## Quick Start

**New here?** Follow the [Getting Started](docs/getting-started.md) guide for a hands-on walkthrough.

```bash
./gradlew :oag-app:shadowJar
java -jar oag-app/build/libs/oag-app-*-all.jar run --policy policy.yaml
```

Use the proxy in your agent:

```
HTTP_PROXY=http://127.0.0.1:8080
HTTPS_PROXY=http://127.0.0.1:8080
```

## Docs

- [Getting Started](docs/getting-started.md) — build, first policy, test, audit
- [Concepts](docs/concepts.md) — architecture, data flow, threat model
- [Configuration](docs/configuration.md) — policy schema, rule fields, bundles, linting
- [CLI Reference](docs/cli.md) — CLI reference (all commands, flags, JSON schemas)
- [Security](docs/security.md) — content inspection, sensitive data, exfiltration guards
- [Observability](docs/observability.md) — audit events, metrics, admin server, OTel
- [Operations](docs/operations.md) — deployment, packaging, resilience, testing
- [Plugins](docs/plugins.md) — custom detector SPI, artifact types, finding model
- [Policy Examples](docs/examples/policy-examples.md) — ready-to-use policy recipes

## License

Licensed under the [Business Source License 1.1](LICENSE).

Free for individuals, non-profits, education, research, and internal use by organizations securing their own AI agents. Commercial use by organizations with >$1M annual revenue requires a [commercial license](mailto:licensing@mustafadakhel.com).

Converts to Apache 2.0 on 2030-03-15.
