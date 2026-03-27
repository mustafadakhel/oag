# OAG Documentation

OAG is a portable egress policy engine, secret materializer, and audit recorder for AI agents. It runs as an HTTP/HTTPS forward proxy between agents and the internet — enforcing what agents can access, injecting secrets they never see, and recording every decision.

## At a Glance

| | |
|---|---|
| **Deny latency** | 0.34 ms (denied requests never touch the network) |
| **Allow overhead** | 1.2 ms (policy eval + DNS + secrets + audit, before upstream I/O) |
| **Denied share** | 94-98% of total request time is upstream network I/O on allowed requests |
| **Policy eval** | 0.08 ms per request (warm path) |
| **Secret materialization** | 0.10-0.12 ms per request |
| **Startup** | < 1s (JVM), instant (native binary) |

| | |
|---|---|
| **Modules** | 10 (core, policy, audit, secrets, inspection, telemetry, enforcement, pipeline, proxy, app) |
| **Source** | ~19K lines Kotlin (main) + ~26K lines (tests) |
| **CLI commands** | 11 (run, doctor, explain, test, hash, bundle, verify, lint, simulate, diff, help) |
| **CLI flags** | 77 configuration options |
| **Reason codes** | 32 distinct deny/allow reasons in audit events |
| **Injection categories** | 6 built-in pattern families + custom patterns + optional ML classifier |
| **Audit event types** | 8 (startup, request, tool, policy_reload, circuit_breaker, policy_fetch, admin_access, integrity_check) |
| **Admin endpoints** | 7 (healthz, metrics, reload, pool, policy, audit, tasks) |
| **Prometheus metrics** | 10 counters/gauges/histograms |
| **Distribution** | Fat JAR (19 MB), native binary (21-27 MB), Docker image |

## Reading Order

| Document | Audience | What you'll learn |
|---|---|---|
| [Getting Started](getting-started.md) | New users | Install, first policy, test, audit |
| [Concepts](concepts.md) | Everyone | Architecture, data flow, threat model, design principles |
| [Configuration Reference](configuration.md) | Policy authors | Full policy schema, rule fields, bundles, linting, agent profiles |
| [CLI Reference](cli.md) | Operators, CI | All commands, flags, JSON output schemas |
| [Security](security.md) | Security engineers | Content inspection, injection detection, exfiltration guards, TLS |
| [Observability](observability.md) | Operators, SRE | Audit events, Prometheus metrics, admin server, OTel, webhooks |
| [Operations](operations.md) | Operators, DevOps | Deployment, packaging, native binary, circuit breaker, troubleshooting |
| [Plugins](plugins.md) | Plugin authors | Custom detector SPI, artifact types, finding model |
| [Policy Examples](examples/policy-examples.md) | Policy authors | Ready-to-use policy recipes |
