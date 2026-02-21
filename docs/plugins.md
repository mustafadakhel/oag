# OAG Detection Plugins

OAG supports custom detection plugins. Build a JAR with your detector logic, place it on the classpath, and register the provider class via `--plugin-provider`. OAG instantiates your provider at startup and integrates its detectors into the pipeline.

## How It Works

1. You implement a `DetectorProvider` that returns `DetectorRegistration`s
2. Each registration binds a `Detector<T>` to an artifact type (`TextBody`, `Headers`, `Url`)
3. OAG's `PluginDetectionPhase` runs your detectors against each request
4. Detectors return `Finding` objects with a `RecommendedAction`
5. All findings appear in the audit log

Each finding carries one or more recommended actions:

- **`DENY`** — Block the request (403 Forbidden).
- **`REDACT`** — Redact matching content from audit event bodies using the detector's redaction patterns (requires implementing `RedactingDetector`).
- **`LOG`** — Include the finding in audit events without blocking or redacting. This is the default if no action is specified.

## SPI Contract

### DetectorProvider

The entry point for a plugin. Must have a no-arg constructor.

```kotlin
interface DetectorProvider {
    val id: String                           // unique provider identifier
    val description: String                  // human-readable description
    val priority: Int get() = 100            // lower = runs first
    fun detectors(): List<DetectorRegistration<*>>
    fun close() {}                           // called on OAG shutdown
}
```

### DetectorRegistration

Binds a detector to the artifact type it inspects.

```kotlin
data class DetectorRegistration<T : InspectableArtifact>(
    val artifactType: Class<T>,              // what to inspect
    val detector: Detector<T>,               // the detection logic
    val findingTypes: Set<FindingType>,       // finding types this detector produces
    val id: String                           // detector ID for policy filtering
)
```

### Detector

The detection logic. Receives an artifact and returns findings.

```kotlin
fun interface Detector<T : InspectableArtifact> {
    fun inspect(input: T, ctx: InspectionContext): List<Finding>
}
```

#### InspectionContext Fields

| Field | Type | Description |
|---|---|---|
| `host` | `String?` | Target hostname of the request |
| `method` | `String?` | HTTP method (GET, POST, etc.) |
| `path` | `String?` | Request path |
| `ruleId` | `String?` | ID of the matched policy rule (null if no rule matched) |
| `agentId` | `String?` | Resolved agent identity |

### RedactingDetector

An optional extension of `Detector` for detectors that also supply redaction patterns. OAG uses these patterns to redact matched content from audit events before writing them.

```kotlin
interface RedactingDetector<T : InspectableArtifact> : Detector<T> {
    fun redactionPatterns(input: T, ctx: InspectionContext): List<RedactionPattern>
}
```

Implement `RedactingDetector` instead of `Detector` when your detector identifies content that should not appear verbatim in audit logs (e.g., tokens, credentials, PII).

## Artifact Types

| Type | Description | Available when |
|------|-------------|----------------|
| `TextBody` | Request body text | Body buffering enabled (content_inspection or plugin_detection configured) |
| `Headers` | HTTP request headers | Always |
| `Url` | Parsed URL (scheme, host, port, path, query) | Always |
| `DnsLabel` | DNS domain label | `PluginDetectionPhase` (host is split by `.` and each label is passed individually) |
| `ResponseTextBody` | Fixed-length upstream response body text, with status code and content type | Response body available and within scan limit |
| `WsFrame` | WebSocket frame text content, with frame type flag | WebSocket relay with plugin detection enabled |
| `StreamingResponseBody` | Accumulated streaming response text up to scan limit, with status code, content type, and truncation flag | Streaming (chunked/SSE) response relay with plugin detection enabled |

## Creating a Plugin

### 1. Project setup

```kotlin
// build.gradle.kts
dependencies {
    compileOnly("com.mustafadakhel:oag-inspection:1.0-SNAPSHOT")
}
```

Your plugin JAR depends only on `oag-inspection` at compile time. OAG provides it at runtime.

### 2. Implement a detector

```kotlin
class PhoneNumberDetector : Detector<TextBody> {
    private val patterns = listOf(
        PatternEntry("us_phone", Regex("""\b\d{3}[-.]?\d{3}[-.]?\d{4}\b""")),
        PatternEntry("intl_phone", Regex("""\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b"""))
    )

    override fun inspect(input: TextBody, ctx: InspectionContext): List<Finding> =
        patterns
            .filter { it.regex.containsMatchIn(input.text) }
            .map { pattern ->
                Finding(
                    type = FindingType.CUSTOM,
                    severity = FindingSeverity.HIGH,
                    confidence = 0.85,
                    location = FindingLocation.Body,
                    evidence = mapOf(
                        EvidenceKey.PATTERN to pattern.name,
                        EvidenceKey.SOURCE to "phone-number-plugin"
                    ),
                    recommendedActions = listOf(RecommendedAction.DENY)
                )
            }
}
```

### 3. Create a provider

```kotlin
class PhoneNumberDetectorProvider : DetectorProvider {
    override val id = "phone-number"
    override val description = "Detects phone numbers in request bodies"

    override fun detectors(): List<DetectorRegistration<*>> = listOf(
        DetectorRegistration(
            artifactType = TextBody::class.java,
            detector = PhoneNumberDetector(),
            findingTypes = setOf(FindingType.CUSTOM),
            id = "phone-number-body"
        )
    )
}
```

### 4. Deploy and register

Place the plugin JAR on OAG's classpath. Register the provider class name at startup:

```bash
oag run --policy policy.yaml \
  --plugin-provider com.example.PhoneNumberDetectorProvider
```

Multiple providers (comma-separated):

```bash
oag run --policy policy.yaml \
  --plugin-provider com.example.PhoneNumberDetectorProvider,com.acme.CustomScannerProvider
```

OAG instantiates each class via `Class.forName()` + no-arg constructor. If a class is missing or fails to load, OAG logs the error and continues with remaining providers.

## Policy Configuration

Control plugin detection per-policy or per-rule:

```yaml
defaults:
  plugin_detection:
    enabled: true
    scan_responses: true                       # enable response-body scanning
    deny_severity_threshold: high              # auto-deny at or above this severity
    # detector_ids: [phone-number-body]        # allow-list (omit = all)
    # exclude_detector_ids: [noisy-detector]   # deny-list
```

- `scan_responses: true` — Required to enable response-body scanning with plugin detectors. Without this, `ResponseTextBody` and `StreamingResponseBody` detectors will never run.
- `deny_severity_threshold: high` — Auto-deny findings at or above this severity, independent of `RecommendedAction.DENY`. Valid values: `low`, `medium`, `high`, `critical`.

Per-rule overrides:

```yaml
allow:
  - id: allow_api
    host: api.example.com
    plugin_detection:
      enabled: true
      detector_ids: [phone-number-body]    # only run this detector for this rule

  - id: allow_internal
    host: "*.internal.corp"
    skip_plugin_detection: true             # disable plugins for this rule
```

**Note:** `TextBody` detectors require body buffering. OAG automatically buffers the request body when `plugin_detection` is configured. If both `plugin_detection` and `content_inspection` are disabled, no body buffering occurs and `TextBody` detectors receive no input.

## Error Handling

- If a provider class is not found or fails to instantiate, OAG logs the error and skips it
- If a detector throws during `inspect()`, OAG catches the error, logs it, and continues with other detectors
- Plugin failures never crash the proxy
- Provider `close()` is called during OAG shutdown for resource cleanup

## Findings in Audit Events

Plugin findings appear in audit events under `content_inspection`:

```json
{
  "content_inspection": {
    "plugin_detector_ids": ["phone-number-body"],
    "plugin_finding_count": 2
  }
}
```

Denied requests show `reason_code: "plugin_detected"` in the decision.

**Note on `content_inspection` emission:** The `content_inspection` field is omitted from the audit event when `isNonTrivial()` returns false. The trivial check covers body inspection, injection patterns, entropy scores, data budgets, response truncation, credential detection, data classification, and path analysis — but does not include plugin-specific fields (`plugin_detector_ids`, `plugin_finding_count`, and their response/streaming equivalents). This means that if plugins fire but no other inspection signals are present, `content_inspection` will be absent from the audit event even though detectors ran and produced findings.

## Finding Suppressions

Policy authors can suppress specific findings using `finding_suppressions` in defaults or per-rule. Suppressed findings are excluded from enforcement decisions but counted in `suppressed_finding_count` in audit events.

```yaml
defaults:
  finding_suppressions:
    - detector_id: noisy-detector
    - finding_type: custom
      hosts: ["internal.example.com"]
    - pattern: "test-.*"
```

Per-rule:

```yaml
allow:
  - id: allow_api
    host: api.example.com
    finding_suppressions:
      - detector_id: noisy-detector
```

Suppression fields:

| Field | Type | Description |
|---|---|---|
| `detector_id` | string | Suppress all findings from this detector |
| `finding_type` | string | Suppress findings of this type |
| `pattern` | string | Regex pattern matched against finding evidence |
| `hosts` | list | Only suppress when the request targets one of these hosts |

All fields are optional within a suppression entry, but at least one of `detector_id`, `finding_type`, or `pattern` must be present. When multiple fields are specified in the same entry, all must match for the suppression to apply.

## Built-in Detectors

OAG's built-in detectors (injection, credentials, data classification) run through dedicated pipeline phases. They are not loaded as plugins — the plugin path is for external/custom detectors only.
