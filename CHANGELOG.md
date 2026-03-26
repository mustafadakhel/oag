# Changelog

## 0.1.0

Initial release.

### Features

- Policy enforcement with deterministic deny-before-allow evaluation
- HTTP/HTTPS forward proxy with CONNECT tunnel support
- TLS interception (MITM) with ephemeral CA and per-host certificates
- WebSocket frame relay with content inspection
- Prompt injection detection with 6 pattern families and heuristic scoring
- Optional ONNX-based ML classifier for injection detection
- Outbound credential detection (AWS keys, GitHub PATs, JWTs, private keys, Slack tokens, API keys)
- Sensitive data classification (PII, financial, credentials)
- URL/DNS exfiltration guards with Shannon entropy analysis
- Path traversal and double-encoding detection
- Plugin SPI for custom detectors with finding suppression
- Secret materialization with ENV, file, and OAuth2 providers
- Connection pooling, circuit breakers, and token bucket rate limiting
- Per-session data and token budget tracking
- Structured audit logging (JSONL) with 8 event types
- Rotating log files with optional GZIP compression
- OpenTelemetry integration (audit logs and distributed tracing)
- 10 Prometheus metrics
- 7 admin API endpoints
- Webhook notifications with HMAC signing
- Policy bundles with Ed25519 signatures
- Policy hot-reload via file watcher, SIGHUP, admin endpoint, and remote fetch
- 11 CLI commands with JSON output mode
