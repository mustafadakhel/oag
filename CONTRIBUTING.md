# Contributing to OAG

Thank you for your interest in contributing to Open Agent Guard.

## Getting Started

**Requirements:**
- JDK 21 (any distribution — Temurin, Corretto, GraalVM, etc.)
- Gradle 8.13+ (wrapper included, no install needed)

**Build and test:**
```bash
./gradlew build
```

**Run locally:**
```bash
./gradlew :oag-app:run --args="run --policy policy.yaml --port 8080"
```

## Project Structure

OAG is a multi-module Gradle project with a strict dependency DAG:

```
oag-core          ← shared utilities, constants, HTTP parsing
oag-policy        ← policy YAML parsing, evaluation, validation
oag-audit         ← audit event models, JSONL logging, file rotation
oag-secrets       ← secret providers (env, file, OAuth2), materialization
oag-inspection    ← content inspection, injection detection, plugin SPI
oag-enforcement   ← circuit breakers, rate limiters, budget trackers
oag-telemetry     ← OpenTelemetry, Prometheus metrics, profiling
oag-pipeline      ← request pipeline, phases, relay, response inspection
oag-proxy         ← proxy server, TLS/MITM, WebSocket, admin API
oag-app           ← CLI entry point, 11 commands
```

Dependencies flow downward. `policy/` never depends on `proxy/`, `audit/` never depends on `proxy/`.

## Making Changes

1. Fork the repo and create a branch from `main`.
2. Make your changes. Follow the existing code style — the codebase is consistent.
3. Add or update tests. Every module has tests; new behavior needs test coverage.
4. Run `./gradlew build` and ensure all tests pass.
5. Open a pull request against `main`.

## Code Style

- Kotlin with expression-body functions where the body is a single expression.
- `@Serializable` data classes for all JSON/YAML I/O — no manual JSON tree-walking.
- `fun interface` over typealias for functional types.
- `data class` over `Pair` for multi-value returns.
- Functional operators (`mapNotNull`, `fold`, `filterValues`) over mutable state.
- All enums get a `.label()` extension for serialization.
- No inline fully-qualified names — use imports.

## Architecture Conventions

- **Phase pattern**: individual pipeline checks implement the `Phase` interface with a `PipelineStage`.
- **MatchDimension pattern**: policy matching dimensions (host, method, path, etc.) implement `MatchDimension` with `matches`, `validate`, `canonicalize`, `normalize`.
- **Validation**: uses `buildList {}` returning `List<ValidationError>` with dot-notation paths.
- **Factory functions**: simple implementations are factory functions returning closures. Complex implementations sit behind `fun interface` types.
- **Constants**: shared constants in the root `oag` package, module-specific constants stay local.

## Testing

```bash
# All tests
./gradlew test

# Single module
./gradlew :oag-policy:test

# Single test class
./gradlew :oag-policy:test --tests "*.PolicyEvaluatorTest"
```

Tests use `kotlin.test` with JUnit 5 as the platform. Coroutine tests use `kotlinx.coroutines.test.runTest`.

## Reporting Issues

Open an issue on GitHub with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Policy YAML (if relevant, redact secrets)

## License

By contributing, you agree that your contributions will be licensed under the same [Business Source License 1.1](LICENSE) as the project.
