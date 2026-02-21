package com.mustafadakhel.oag.audit

import com.mustafadakhel.oag.telemetry.OtelAuditLogger
import com.mustafadakhel.oag.telemetry.OtelConfig
import com.mustafadakhel.oag.telemetry.OtelExporterType

import io.opentelemetry.sdk.logs.SdkLoggerProvider
import io.opentelemetry.sdk.logs.export.SimpleLogRecordProcessor
import io.opentelemetry.sdk.testing.exporter.InMemoryLogRecordExporter
import kotlinx.serialization.json.Json

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class AuditLoggerTest {

    private val testJson = Json { ignoreUnknownKeys = true }

    private inline fun <reified T> parseFirst(out: ByteArrayOutputStream): T =
        testJson.decodeFromString<T>(out.toString(Charsets.UTF_8).lineSequence().first { it.isNotBlank() })

    @Test
    fun `audit logger emits json line`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        val event = AuditEvent(
            oagVersion = "0.1.0",
            policyHash = "abc",
            agentId = null,
            sessionId = null,
            request = AuditRequest(
                host = "api.example.com",
                port = 443,
                scheme = "https",
                method = "GET",
                path = "/",
                bytesOut = 0,
                resolvedIps = emptyList()
            ),
            response = AuditResponse(bytesIn = 0, status = 200),
            decision = AuditDecision("allow", "rule1", "allowed_by_rule"),
            secrets = AuditSecrets(false, false, emptyList(), emptyMap())
        )
        logger.log(event)
        val parsed = parseFirst<AuditEvent>(out)

        assertEquals(AUDIT_SCHEMA_VERSION, parsed.schemaVersion)
        assertTrue(parsed.timestamp!!.isNotBlank())
        assertEquals("0.1.0", parsed.oagVersion)
        assertEquals("abc", parsed.policyHash)
        assertEquals("allow", parsed.decision.action)
        assertEquals("allowed_by_rule", parsed.decision.reasonCode)
        assertEquals(200, parsed.response?.status)
    }

    @Test
    fun `audit event contract includes required top level fields`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        logger.log(
            AuditEvent(
                oagVersion = "0.1.0",
                policyHash = "abc",
                agentId = "agent-1",
                sessionId = "session-1",
                request = AuditRequest("api.example.com", 443, "https", "GET", "/", 0, emptyList()),
                response = AuditResponse(42, status = 200),
                decision = AuditDecision("deny", null, "no_match_default_deny"),
                secrets = AuditSecrets(false, false, emptyList(), emptyMap())
            )
        )

        val parsed = parseFirst<AuditEvent>(out)
        assertNotNull(parsed.timestamp)
        assertEquals(AUDIT_SCHEMA_VERSION, parsed.schemaVersion)
        assertEquals("0.1.0", parsed.oagVersion)
        assertEquals("abc", parsed.policyHash)
        assertEquals("agent-1", parsed.agentId)
        assertEquals("session-1", parsed.sessionId)
        assertNotNull(parsed.request)
        assertNotNull(parsed.response)
        assertNotNull(parsed.decision)
        assertNotNull(parsed.secrets)
    }

    @Test
    fun `audit event includes request decision secrets and error fields`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        logger.log(
            AuditEvent(
                oagVersion = "0.1.0",
                policyHash = "abc",
                agentId = "agent-1",
                sessionId = "session-1",
                request = AuditRequest("api.example.com", 443, "https", "POST", "/v1/chat", 128, emptyList()),
                response = AuditResponse(256, status = 403),
                decision = AuditDecision("deny", "rule-1", "secret_materialization_failed"),
                secrets = AuditSecrets(true, false, listOf("OPENAI_KEY"), mapOf("OPENAI_KEY" to "v1")),
                errors = listOf(AuditError("secret_materialization_failed", "secret_missing:OPENAI_KEY"))
            )
        )

        val parsed = parseFirst<AuditEvent>(out)
        assertEquals("api.example.com", parsed.request.host)
        assertEquals("POST", parsed.request.method)
        assertTrue(parsed.request.resolvedIps.isEmpty())
        assertEquals("deny", parsed.decision.action)
        assertEquals("secret_materialization_failed", parsed.decision.reasonCode)
        assertEquals(true, parsed.secrets.injectionAttempted)
        assertEquals("OPENAI_KEY", parsed.secrets.secretIds[0])
        assertEquals("v1", parsed.secrets.secretVersions["OPENAI_KEY"])
        assertEquals("secret_materialization_failed", parsed.errors[0].code)
    }

    @Test
    fun `tool audit event includes schema version and tool fields`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        logger.logToolEvent(
            AuditToolEvent(
                oagVersion = "0.1.0",
                policyHash = "abc",
                agentId = "agent-1",
                sessionId = "session-1",
                tool = AuditTool(
                    name = "web.search",
                    parameterKeys = listOf("query"),
                    parameters = mapOf("query" to "[REDACTED]"),
                    responseBytes = 12,
                    durationMs = 4,
                    errorCode = null
                )
            )
        )

        val parsed = parseFirst<AuditToolEvent>(out)
        assertEquals(AUDIT_SCHEMA_VERSION, parsed.schemaVersion)
        assertEquals("web.search", parsed.tool.name)
        assertEquals("[REDACTED]", parsed.tool.parameters["query"])
    }

    @Test
    fun `startup audit event includes policy hash and config`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        logger.logStartupEvent(
            AuditStartupEvent(
                oagVersion = "0.1.0",
                policyHash = "abc123",
                agentId = "agent-1",
                sessionId = "session-1",
                config = AuditStartupConfig(
                    policyPath = "policy.yaml",
                    policyPublicKeyPath = null,
                    policyRequireSignature = false,
                    logPath = "logs/audit.jsonl",
                    listenHost = "0.0.0.0",
                    listenPort = 8080,
                    maxThreads = 32,
                    secretEnvPrefix = "OAG_SECRET_",
                    secretProvider = "env",
                    secretFileDir = null,
                    dryRun = false,
                    blockIpLiterals = true,
                    enforceRedirectPolicy = true,
                    blockPrivateResolvedIps = true,
                    connectTimeoutMs = 5000,
                    readTimeoutMs = 30000,
                    otelExporter = "none",
                    otelEndpoint = null,
                    otelHeadersKeys = emptyList(),
                    otelTimeoutMs = null,
                    otelServiceName = null
                )
            )
        )

        val parsed = parseFirst<AuditStartupEvent>(out)
        assertEquals(AUDIT_SCHEMA_VERSION, parsed.schemaVersion)
        assertEquals(AuditEventType.STARTUP, parsed.eventType)
        assertEquals("abc123", parsed.policyHash)
        assertEquals("policy.yaml", parsed.config.policyPath)
        assertNull(parsed.config.policyPublicKeyPath)
        assertEquals(false, parsed.config.policyRequireSignature)
        assertEquals("logs/audit.jsonl", parsed.config.logPath)
        assertEquals(true, parsed.config.blockIpLiterals)
        assertEquals(5000, parsed.config.connectTimeoutMs)
        assertEquals("none", parsed.config.otelExporter)
    }

    @Test
    fun `audit event includes content inspection when present`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        logger.log(
            AuditEvent(
                oagVersion = "0.1.0",
                policyHash = "abc",
                agentId = null,
                sessionId = "s1",
                request = AuditRequest("api.example.com", 443, "https", "POST", "/v1/chat", 512, emptyList()),
                response = AuditResponse(0, status = 403),
                decision = AuditDecision("deny", null, "injection_detected"),
                secrets = AuditSecrets(false, false, emptyList(), emptyMap()),
                contentInspection = AuditContentInspection(
                    bodyInspected = true,
                    injectionPatternsMatched = listOf("chatml_delimiter", "custom:badword"),
                    urlEntropyScore = 3.2,
                    dnsEntropyScore = null,
                    dataBudgetUsedBytes = 1024
                )
            )
        )

        val parsed = parseFirst<AuditEvent>(out)
        val ci = parsed.contentInspection!!
        assertEquals(true, ci.bodyInspected)
        assertEquals(2, ci.injectionPatternsMatched!!.size)
        assertEquals("chatml_delimiter", ci.injectionPatternsMatched!![0])
        assertEquals(3.2, ci.urlEntropyScore!!, 0.01)
        assertNull(ci.dnsEntropyScore)
        assertEquals(1024, ci.dataBudgetUsedBytes)
    }

    @Test
    fun `audit event omits content inspection when null`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        logger.log(
            AuditEvent(
                oagVersion = "0.1.0",
                policyHash = "abc",
                agentId = null,
                sessionId = null,
                request = AuditRequest("api.example.com", 443, "https", "GET", "/", 0, emptyList()),
                response = AuditResponse(0, status = 200),
                decision = AuditDecision("allow", null, "allowed_by_rule"),
                secrets = AuditSecrets(false, false, emptyList(), emptyMap())
            )
        )

        val parsed = parseFirst<AuditEvent>(out)
        assertNull(parsed.contentInspection)
    }

    @Test
    fun `otel failure does not prevent jsonl write for request event`() {
        val out = ByteArrayOutputStream()
        val exporter = InMemoryLogRecordExporter.create()
        val provider = SdkLoggerProvider.builder()
            .addLogRecordProcessor(SimpleLogRecordProcessor.create(exporter))
            .build()
        val otelConfig = OtelConfig(exporter = OtelExporterType.STDOUT, serviceName = "oag-test")
        val otelLogger = OtelAuditLogger(otelConfig, "0.0.0-test", providerOverride = provider)
        provider.shutdown()

        val stderrCapture = ByteArrayOutputStream()
        val originalErr = System.err
        System.setErr(PrintStream(stderrCapture))
        try {
            val logger = AuditLogger(out, externalSink = otelLogger)
            logger.log(
                AuditEvent(
                    oagVersion = "0.1.0",
                    policyHash = "abc",
                    agentId = null,
                    sessionId = null,
                    request = AuditRequest("api.example.com", 443, "https", "GET", "/", 0, emptyList()),
                    response = AuditResponse(0, status = 200),
                    decision = AuditDecision("allow", null, "allowed_by_rule"),
                    secrets = AuditSecrets(false, false, emptyList(), emptyMap())
                )
            )
            val parsed = parseFirst<AuditEvent>(out)
            assertEquals("allow", parsed.decision.action)
        } finally {
            System.setErr(originalErr)
        }
    }

    @Test
    fun `otel failure does not prevent jsonl write for tool event`() {
        val out = ByteArrayOutputStream()
        val exporter = InMemoryLogRecordExporter.create()
        val provider = SdkLoggerProvider.builder()
            .addLogRecordProcessor(SimpleLogRecordProcessor.create(exporter))
            .build()
        val otelConfig = OtelConfig(exporter = OtelExporterType.STDOUT, serviceName = "oag-test")
        val otelLogger = OtelAuditLogger(otelConfig, "0.0.0-test", providerOverride = provider)
        provider.shutdown()

        val stderrCapture = ByteArrayOutputStream()
        val originalErr = System.err
        System.setErr(PrintStream(stderrCapture))
        try {
            val logger = AuditLogger(out, externalSink = otelLogger)
            logger.logToolEvent(
                AuditToolEvent(
                    oagVersion = "0.1.0",
                    policyHash = "abc",
                    agentId = null,
                    sessionId = null,
                    tool = AuditTool("test", emptyList(), emptyMap(), null, null, null)
                )
            )
            val parsed = parseFirst<AuditToolEvent>(out)
            assertEquals("test", parsed.tool.name)
        } finally {
            System.setErr(originalErr)
        }
    }

    @Test
    fun `otel failure does not prevent jsonl write for startup event`() {
        val out = ByteArrayOutputStream()
        val exporter = InMemoryLogRecordExporter.create()
        val provider = SdkLoggerProvider.builder()
            .addLogRecordProcessor(SimpleLogRecordProcessor.create(exporter))
            .build()
        val otelConfig = OtelConfig(exporter = OtelExporterType.STDOUT, serviceName = "oag-test")
        val otelLogger = OtelAuditLogger(otelConfig, "0.0.0-test", providerOverride = provider)
        provider.shutdown()

        val stderrCapture = ByteArrayOutputStream()
        val originalErr = System.err
        System.setErr(PrintStream(stderrCapture))
        try {
            val logger = AuditLogger(out, externalSink = otelLogger)
            logger.logStartupEvent(
                AuditStartupEvent(
                    oagVersion = "0.1.0",
                    policyHash = "abc",
                    agentId = null,
                    sessionId = null,
                    config = AuditStartupConfig(
                        policyPath = "policy.yaml",
                        policyPublicKeyPath = null,
                        policyRequireSignature = false,
                        logPath = null,
                        listenHost = "0.0.0.0",
                        listenPort = 8080,
                        maxThreads = 32,
                        secretEnvPrefix = "OAG_SECRET_",
                        secretProvider = "env",
                        secretFileDir = null,
                        dryRun = false,
                        blockIpLiterals = false,
                        enforceRedirectPolicy = false,
                        blockPrivateResolvedIps = false,
                        connectTimeoutMs = 5000,
                        readTimeoutMs = 30000,
                        otelExporter = "none",
                        otelEndpoint = null,
                        otelHeadersKeys = emptyList(),
                        otelTimeoutMs = null,
                        otelServiceName = null
                    )
                )
            )
            val parsed = parseFirst<AuditStartupEvent>(out)
            assertEquals(AuditEventType.STARTUP, parsed.eventType)
        } finally {
            System.setErr(originalErr)
        }
    }

    @Test
    fun `policy reload event includes previous and new hash`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        logger.logPolicyReloadEvent(
            AuditPolicyReloadEvent(
                oagVersion = "0.1.0",
                previousPolicyHash = "hash_v1",
                newPolicyHash = "hash_v2",
                changed = true,
                success = true,
                agentId = "agent-1",
                sessionId = "session-1"
            )
        )

        val parsed = parseFirst<AuditPolicyReloadEvent>(out)
        assertEquals(AUDIT_SCHEMA_VERSION, parsed.schemaVersion)
        assertEquals(AuditEventType.POLICY_RELOAD, parsed.eventType)
        assertEquals("hash_v1", parsed.previousPolicyHash)
        assertEquals("hash_v2", parsed.newPolicyHash)
        assertEquals(true, parsed.changed)
        assertEquals(true, parsed.success)
        assertTrue(parsed.timestamp!!.isNotBlank())
    }

    @Test
    fun `policy reload failure event includes error message`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        logger.logPolicyReloadEvent(
            AuditPolicyReloadEvent(
                oagVersion = "0.1.0",
                previousPolicyHash = "hash_v1",
                newPolicyHash = null,
                changed = false,
                success = false,
                errorMessage = "Invalid YAML",
                agentId = null,
                sessionId = null
            )
        )

        val parsed = parseFirst<AuditPolicyReloadEvent>(out)
        assertEquals(AuditEventType.POLICY_RELOAD, parsed.eventType)
        assertEquals(false, parsed.success)
        assertEquals("Invalid YAML", parsed.errorMessage)
        assertNull(parsed.newPolicyHash)
    }

    @Test
    fun `circuit breaker event includes host and state transition`() {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        logger.logCircuitBreakerEvent(
            AuditCircuitBreakerEvent(
                oagVersion = "0.1.0",
                host = "api.failing.com",
                previousState = "closed",
                newState = "open",
                agentId = "agent-1",
                sessionId = "session-1"
            )
        )

        val parsed = parseFirst<AuditCircuitBreakerEvent>(out)
        assertEquals(AUDIT_SCHEMA_VERSION, parsed.schemaVersion)
        assertEquals(AuditEventType.CIRCUIT_BREAKER, parsed.eventType)
        assertEquals("api.failing.com", parsed.host)
        assertEquals("closed", parsed.previousState)
        assertEquals("open", parsed.newState)
        assertTrue(parsed.timestamp!!.isNotBlank())
    }

    @Test
    fun `audit logger keeps json lines intact under concurrent writes`() = runBlocking {
        val out = ByteArrayOutputStream()
        val logger = AuditLogger(out)
        val workers = 16
        val perWorker = 20
        val done = CountDownLatch(workers)

        repeat(workers) { workerId ->
            launch(Dispatchers.Default) {
                repeat(perWorker) { index ->
                    logger.log(
                        AuditEvent(
                            oagVersion = "0.1.0",
                            policyHash = "abc",
                            agentId = "agent-$workerId",
                            sessionId = "session-$index",
                            request = AuditRequest("api.example.com", 443, "https", "GET", "/", 0, emptyList()),
                            response = AuditResponse(0, status = 200),
                            decision = AuditDecision("allow", null, "allowed_by_rule"),
                            secrets = AuditSecrets(false, false, emptyList(), emptyMap())
                        )
                    )
                }
                done.countDown()
            }
        }

        assertTrue(done.await(5, TimeUnit.SECONDS), "timed out waiting for logging workers")
        val lines = out.toString(Charsets.UTF_8).lineSequence().filter { it.isNotBlank() }.toList()
        assertEquals(workers * perWorker, lines.size)
        lines.forEach { line ->
            val parsed = testJson.decodeFromString<AuditEvent>(line)
            assertEquals(AUDIT_SCHEMA_VERSION, parsed.schemaVersion)
            assertTrue(parsed.timestamp!!.isNotBlank())
        }
    }
}
