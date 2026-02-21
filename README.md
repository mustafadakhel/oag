# Open Agent Guard (OAG)

Portable runtime policy and audit layer for AI agents. OAG provides:

- Egress policy enforcement (HTTP/HTTPS proxy).
- Secret materialization at request time.
- Structured audit logging (JSONL).

It is not a sandbox and does not own the compute plane.

## Features

- Deterministic policy evaluation (deny > allow).
- HTTP/HTTPS proxy with CONNECT support.
- Secret scopes (`secret_scopes`) and placeholder-based injection.
- Secret providers: env and file.
- Audit logs with policy hash, reason codes, and redirect chain evidence (when redirect enforcement is enabled).
- DNS enforcement (`enforce_dns_resolution`) with `resolved_ips` in audit for all request types.
- Optional OpenTelemetry log export for audit events.
- Trace correlation fields from `traceparent`.
- Policy bundles with optional Ed25519 signatures.

## Dependencies

OAG keeps its dependency set focused on three areas:

| Category | Libraries | Why |
|----------|-----------|-----|
| Serialization | kotlinx.serialization + kotaml (YAML) | Policy YAML parsing, audit JSONL output |
| Cryptography | BouncyCastle (bcprov, bcpkix) | Ed25519 bundle signatures, HMAC, TLS CA generation |
| Observability | OpenTelemetry SDK + exporters | Optional audit log export via OTLP/gRPC |
| Async | kotlinx-coroutines-core | Webhook delivery, background policy fetching |

HTTP parsing, connection pooling, and the CLI parser are hand-rolled to avoid
pulling in a full web framework for what is fundamentally a TCP proxy.

## Compatibility

- Kotlin: 2.2.20 (JVM)
- JDK: 21 (toolchain)

## Quick Start

**New here?** Follow the [Getting Started](docs/getting-started.md) guide for a hands-on walkthrough.

```bash
./gradlew :oag-app:run --args="run --policy policy.yaml --port 8080 --log audit.jsonl"
```

Use the proxy in your agent:

- `HTTP_PROXY=http://127.0.0.1:8080`
- `HTTPS_PROXY=http://127.0.0.1:8080`

## Docs

- [`docs/getting-started.md`](docs/getting-started.md) — build, first policy, test, audit
- [`docs/concepts.md`](docs/concepts.md) — architecture, data flow, threat model
- [`docs/configuration.md`](docs/configuration.md) — policy schema, rule fields, bundles, linting
- [`docs/cli.md`](docs/cli.md) — CLI reference (all commands, flags, JSON schemas)
- [`docs/security.md`](docs/security.md) — content inspection, sensitive data, exfiltration guards
- [`docs/observability.md`](docs/observability.md) — audit events, metrics, admin server, OTel
- [`docs/operations.md`](docs/operations.md) — deployment, packaging, resilience, testing

## License

Licensed under the [Business Source License 1.1](LICENSE).

Free for individuals, non-profits, education, research, and internal use by organizations securing their own AI agents. Commercial use by organizations with >$1M annual revenue requires a [commercial license](mailto:licensing@mustafadakhel.com).

Converts to Apache 2.0 on 2030-03-15.
