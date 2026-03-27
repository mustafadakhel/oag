# Changelog

## 0.1.9

### Performance

- Install UPX on all platforms (Linux, macOS, Windows) for native binary compression — previously only Linux binaries were compressed

## 0.1.8

### Bug Fixes

- Fix `-Os` native-image flag incompatible with GraalVM CE 21.0.2

## 0.1.7

### Bug Fixes

- Fix `isNonTrivial()` audit check to include plugin finding fields — previously, `content_inspection` was silently omitted from audit events when only plugin detectors fired
- Generate request IDs at IDENTITY stage so denied requests get IDs in audit events — previously, request IDs were only assigned to allowed requests that reached the ACTIONS stage

### Security

- Add `OAG_ADMIN_TOKEN` environment variable as alternative to `--admin-token` CLI flag — keeps credentials out of the process list
- Add `OAG_MTLS_KEYSTORE_PASSWORD` environment variable as alternative to `--mtls-keystore-password` CLI flag

### Performance

- Strip debug symbols and UPX-compress native Linux binaries in release workflow

## 0.1.6

### Security

- Add `OAG_ADMIN_TOKEN` and `OAG_MTLS_KEYSTORE_PASSWORD` environment variable alternatives for sensitive CLI flags

## 0.1.5

### Features

- ML classifier `trigger_mode` is now configurable via policy YAML (`always` or `uncertain_only`) with tunable `uncertain_low`/`uncertain_high` bounds
- `tokenizer_path` now loads a HuggingFace tokenizer when DJL is on the classpath — falls back to char-code encoding when absent
- Tokenizer interface (`Tokenizer`, `CharCodeTokenizer`, `DjlHuggingFaceTokenizer`) for pluggable tokenization in the ML classifier
- Dockerfile with JRE-based image (temurin:21-jre-alpine)
- Docker image publishing to ghcr.io in release workflow with semver tags
- GraalVM native binary builds for Linux, macOS (x64/arm64), and Windows

### Refactoring

- Remove `TrafficUnit.AdminRequest` (unused dead code)
- Add pipeline phase ordering validation (`producesKeys` on Phase interface)
- Replace `PolicyCapability` sealed interface with `shouldNotifyWebhook` extension
- Extract `ScopeMatching.kt` with shared scope matching and normalization functions
- Extract `matchingNames` extension for `List<PatternEntry>`
- Add `PolicyRetry.toRetryPolicy()` extension
- Document `resolvedAgentId` three-source priority; rename `certificateIdentityProvider` to `extractCertificateIdentity`
- Collapse `PipelineError` into `OagRequestException`

### Documentation

- Fix 44 doc-code alignment issues across all 10 documentation files
- Fix broken `deny_threshold: 2.0` example in policy-examples.md
- Fix index.md statistics (reason codes 17→32, admin endpoints 6→7, metrics 7→10)
- Add missing fields to configuration.md (plugin detection, finding suppressions, webhook events)
- Add distributed tracing section to observability.md
- Add MkDocs with Material theme and GitHub Pages deployment
- Add CONTRIBUTING.md
- Add live-test artifacts (policies, test cases, performance report)
- Update README to reflect all current features

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
