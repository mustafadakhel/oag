# Changelog

## E22-E26: Feature Delivery & Architecture Reconciliation

Features shipped across E22-E26 that were previously tracked in `future-features-plan.md`:

- **Finding suppression** — `PolicyFindingSuppression` in policy defaults and per-rule, wired in `ContentInspectionPhase`, `CredentialsPhase`, `DataClassificationPhase`, `PluginDetectionPhase`
- **Response scanning via plugin SPI** — `ResponseCredentialDetector`, `ResponseSensitiveDataDetector` wired via `DetectorRegistry`, buffered and streaming paths
- **WebSocket frame inspection** — `WebSocketInspector` with direction-aware scanning (injection, credentials, data classification, plugin detectors), close code 4403 on deny
- **Token usage extraction** — `TokenUsageExtractor` in both buffered and streaming response paths, `TokenBudgetPhase` for per-session limits
- **Response redaction** — `PolicyResponseRewrite.Redact` with regex replacement on buffered responses, content-length adjustment, plugin-driven redaction via `FindingRedactionKey`

Additional E26 work:
- Pipeline stage cleanup (removed `CONTEXT_BUILD`, `RELAY`, `EMIT` stages)
- Correct stage assignments for 20/30 phases
- Removed unused `PolicyCapability` subtypes (`SecretInjection`, `Inspect`, `RateLimit`, `TlsInspect`, `Rewrite`, `ResponseControl`)
- Removed `StageSet.RESPONSE`, `StageSet.WS_FRAME`, `StageSet.ADMIN`
