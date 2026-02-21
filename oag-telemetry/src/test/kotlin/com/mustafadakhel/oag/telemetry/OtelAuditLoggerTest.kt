package com.mustafadakhel.oag.telemetry

import com.mustafadakhel.oag.audit.AuditDecision
import com.mustafadakhel.oag.audit.AuditError
import com.mustafadakhel.oag.audit.AuditEvent
import com.mustafadakhel.oag.audit.AuditRedirectHop
import com.mustafadakhel.oag.audit.AuditRequest
import com.mustafadakhel.oag.audit.AuditResponse
import com.mustafadakhel.oag.audit.AuditSecrets
import com.mustafadakhel.oag.audit.AuditStartupConfig
import com.mustafadakhel.oag.audit.AuditStartupEvent
import com.mustafadakhel.oag.audit.AuditTool
import com.mustafadakhel.oag.audit.AuditToolEvent
import com.mustafadakhel.oag.audit.AuditTrace

import io.opentelemetry.api.logs.Severity
import io.opentelemetry.sdk.logs.SdkLoggerProvider
import io.opentelemetry.sdk.logs.export.SimpleLogRecordProcessor
import io.opentelemetry.sdk.testing.exporter.InMemoryLogRecordExporter

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OtelAuditLoggerTest {

    private data class TestHarness(
        val exporter: InMemoryLogRecordExporter,
        val logger: OtelAuditLogger
    )

    private fun harness(): TestHarness {
        val exporter = InMemoryLogRecordExporter.create()
        val provider = SdkLoggerProvider.builder()
            .addLogRecordProcessor(SimpleLogRecordProcessor.create(exporter))
            .build()
        val config = OtelConfig(exporter = OtelExporterType.STDOUT, serviceName = "oag-test")
        val logger = OtelAuditLogger(config, "0.0.0-test", providerOverride = provider)
        return TestHarness(exporter, logger)
    }

    private fun sampleEvent(
        trace: AuditTrace? = null,
        agentId: String? = "agent-1",
        sessionId: String? = "session-1",
        secretIds: List<String> = emptyList(),
        secretVersions: Map<String, String> = emptyMap(),
        resolvedIps: List<String> = emptyList(),
        redirectChain: List<AuditRedirectHop> = emptyList(),
        errors: List<AuditError> = emptyList(),
        ruleId: String? = "rule-1"
    ) = AuditEvent(
        oagVersion = "0.0.0-test",
        policyHash = "abc123",
        agentId = agentId,
        sessionId = sessionId,
        trace = trace,
        request = AuditRequest(
            host = "api.example.com",
            port = 443,
            scheme = "https",
            method = "POST",
            path = "/v1/chat",
            bytesOut = 100,
            resolvedIps = resolvedIps
        ),
        response = AuditResponse(bytesIn = 200, status = 200),
        decision = AuditDecision(action = "allow", ruleId = ruleId, reasonCode = "matched"),
        secrets = AuditSecrets(
            injectionAttempted = secretIds.isNotEmpty(),
            injected = secretIds.isNotEmpty(),
            secretIds = secretIds,
            secretVersions = secretVersions
        ),
        redirectChain = redirectChain,
        errors = errors
    )

    private fun sampleToolEvent() = AuditToolEvent(
        oagVersion = "0.0.0-test",
        policyHash = "abc123",
        agentId = "agent-1",
        sessionId = "session-1",
        tool = AuditTool(
            name = "read_file",
            parameterKeys = listOf("path", "encoding"),
            parameters = mapOf("path" to "/tmp/test.txt", "encoding" to "utf-8"),
            responseBytes = 1024,
            durationMs = 50,
            errorCode = null
        )
    )

    private fun sampleStartupEvent() = AuditStartupEvent(
        oagVersion = "0.0.0-test",
        policyHash = "abc123",
        agentId = "agent-1",
        sessionId = "session-1",
        config = AuditStartupConfig(
            policyPath = "/etc/oag/policy.yaml",
            policyPublicKeyPath = null,
            policyRequireSignature = false,
            logPath = "/var/log/oag/audit.jsonl",
            listenHost = "127.0.0.1",
            listenPort = 8080,
            maxThreads = 32,
            secretEnvPrefix = "OAG_SECRET_",
            secretProvider = "env",
            secretFileDir = null,
            dryRun = false,
            blockIpLiterals = true,
            enforceRedirectPolicy = false,
            blockPrivateResolvedIps = true,
            connectTimeoutMs = 5000,
            readTimeoutMs = 30000,
            otelExporter = "stdout",
            otelEndpoint = null,
            otelHeadersKeys = emptyList(),
            otelTimeoutMs = null,
            otelServiceName = "oag-test"
        )
    )

    @Test
    fun `request event has correct body and severity`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent())
        val records = testHarness.exporter.finishedLogRecordItems
        assertEquals(1, records.size)
        @Suppress("DEPRECATION")
        assertEquals(OagAttributes.BODY_REQUEST, records[0].body.asString())
        assertEquals(Severity.INFO, records[0].severity)
    }

    @Test
    fun `request event has core attributes`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent())
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals("request", attrs[OagAttributes.EVENT_TYPE])
        assertEquals("abc123", attrs[OagAttributes.POLICY_HASH])
        assertEquals("allow", attrs[OagAttributes.DECISION_ACTION])
        assertEquals("matched", attrs[OagAttributes.DECISION_REASON_CODE])
        assertEquals("POST", attrs[OagAttributes.HTTP_REQUEST_METHOD])
        assertEquals("https", attrs[OagAttributes.URL_SCHEME])
        assertEquals("api.example.com", attrs[OagAttributes.SERVER_ADDRESS])
        assertEquals(443L, attrs[OagAttributes.SERVER_PORT])
        assertEquals("/v1/chat", attrs[OagAttributes.URL_PATH])
        assertEquals(100L, attrs[OagAttributes.REQUEST_BYTES_OUT])
        assertEquals(200L, attrs[OagAttributes.HTTP_RESPONSE_STATUS_CODE])
        assertEquals(200L, attrs[OagAttributes.RESPONSE_BYTES_IN])
    }

    @Test
    fun `request event includes optional agent and session ids`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent())
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals("agent-1", attrs[OagAttributes.AGENT_ID])
        assertEquals("session-1", attrs[OagAttributes.SESSION_ID])
        assertEquals("rule-1", attrs[OagAttributes.DECISION_RULE_ID])
    }

    @Test
    fun `request event omits optional fields when null`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(agentId = null, sessionId = null, ruleId = null))
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertNull(attrs[OagAttributes.AGENT_ID])
        assertNull(attrs[OagAttributes.SESSION_ID])
        assertNull(attrs[OagAttributes.DECISION_RULE_ID])
    }

    @Test
    fun `request event includes secret ids and versions when present`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(
            secretIds = listOf("KEY1", "KEY2"),
            secretVersions = mapOf("KEY1" to "v2", "KEY2" to "v3")
        ))
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertTrue(attrs[OagAttributes.SECRETS_INJECTED]!!)
        assertTrue(attrs[OagAttributes.SECRETS_INJECTION_ATTEMPTED]!!)
        assertEquals(listOf("KEY1", "KEY2"), attrs[OagAttributes.SECRETS_IDS])
        val versions = attrs[OagAttributes.SECRETS_VERSIONS]!!
        assertTrue(versions.contains("KEY1=v2"))
        assertTrue(versions.contains("KEY2=v3"))
    }

    @Test
    fun `request event omits secret ids when empty`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent())
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertFalse(attrs[OagAttributes.SECRETS_INJECTED]!!)
        assertNull(attrs[OagAttributes.SECRETS_IDS])
    }

    @Test
    fun `request event includes resolved ips when present`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(resolvedIps = listOf("93.184.216.34", "2001:db8::1")))
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals(
            listOf("93.184.216.34", "2001:db8::1"),
            attrs[OagAttributes.REQUEST_RESOLVED_IPS]
        )
    }

    @Test
    fun `request event omits resolved ips when empty`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent())
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertNull(attrs[OagAttributes.REQUEST_RESOLVED_IPS])
    }

    @Test
    fun `request event includes redirect chain when present`() {
        val hop = AuditRedirectHop(
            status = 301,
            location = "https://new.example.com/path",
            targetHost = "new.example.com",
            targetPort = 443,
            targetScheme = "https",
            targetPath = "/path"
        )
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(redirectChain = listOf(hop)))
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals(1L, attrs[OagAttributes.REDIRECT_COUNT])
        assertEquals(listOf("https://new.example.com/path"), attrs[OagAttributes.REDIRECT_LOCATIONS])
    }

    @Test
    fun `request event includes errors when present`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(errors = listOf(AuditError(code = "invalid_request", message = "bad"))))
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals(listOf("invalid_request:bad"), attrs[OagAttributes.ERRORS])
    }

    @Test
    fun `tool event has correct body and attributes`() {
        val testHarness = harness()
        testHarness.logger.log(sampleToolEvent())
        val record = testHarness.exporter.finishedLogRecordItems[0]
        @Suppress("DEPRECATION")
        assertEquals(OagAttributes.BODY_TOOL, record.body.asString())
        assertEquals(Severity.INFO, record.severity)
        val attrs = record.attributes
        assertEquals("tool", attrs[OagAttributes.EVENT_TYPE])
        assertEquals("read_file", attrs[OagAttributes.TOOL_NAME])
        assertEquals("abc123", attrs[OagAttributes.POLICY_HASH])
        assertEquals("agent-1", attrs[OagAttributes.AGENT_ID])
        assertEquals("session-1", attrs[OagAttributes.SESSION_ID])
        assertEquals(listOf("path", "encoding"), attrs[OagAttributes.TOOL_PARAMETER_KEYS])
        assertEquals(1024L, attrs[OagAttributes.TOOL_RESPONSE_BYTES])
        assertEquals(50L, attrs[OagAttributes.TOOL_DURATION_MS])
    }

    @Test
    fun `tool event omits optional fields when null`() {
        val event = AuditToolEvent(
            oagVersion = "0.0.0-test",
            policyHash = null,
            agentId = null,
            sessionId = null,
            tool = AuditTool(
                name = "run",
                parameterKeys = emptyList(),
                parameters = emptyMap(),
                responseBytes = null,
                durationMs = null,
                errorCode = null
            )
        )
        val testHarness = harness()
        testHarness.logger.log(event)
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals("run", attrs[OagAttributes.TOOL_NAME])
        assertNull(attrs[OagAttributes.POLICY_HASH])
        assertNull(attrs[OagAttributes.AGENT_ID])
        assertNull(attrs[OagAttributes.TOOL_RESPONSE_BYTES])
        assertNull(attrs[OagAttributes.TOOL_DURATION_MS])
        assertNull(attrs[OagAttributes.TOOL_ERROR_CODE])
    }

    @Test
    fun `tool event includes error code when present`() {
        val event = sampleToolEvent().copy(
            tool = sampleToolEvent().tool.copy(errorCode = "timeout")
        )
        val testHarness = harness()
        testHarness.logger.log(event)
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals("timeout", attrs[OagAttributes.TOOL_ERROR_CODE])
    }

    @Test
    fun `startup event has correct body and core attributes`() {
        val testHarness = harness()
        testHarness.logger.log(sampleStartupEvent())
        val record = testHarness.exporter.finishedLogRecordItems[0]
        @Suppress("DEPRECATION")
        assertEquals(OagAttributes.BODY_STARTUP, record.body.asString())
        assertEquals(Severity.INFO, record.severity)
        val attrs = record.attributes
        assertEquals("startup", attrs[OagAttributes.EVENT_TYPE])
        assertEquals("abc123", attrs[OagAttributes.POLICY_HASH])
        assertEquals("/etc/oag/policy.yaml", attrs[OagAttributes.CONFIG_POLICY_PATH])
        assertEquals("127.0.0.1", attrs[OagAttributes.CONFIG_LISTEN_HOST])
        assertEquals(8080L, attrs[OagAttributes.CONFIG_LISTEN_PORT])
        assertEquals(32L, attrs[OagAttributes.CONFIG_MAX_THREADS])
        assertEquals("OAG_SECRET_", attrs[OagAttributes.CONFIG_SECRET_ENV_PREFIX])
        assertEquals("env", attrs[OagAttributes.CONFIG_SECRET_PROVIDER])
        assertFalse(attrs[OagAttributes.CONFIG_DRY_RUN]!!)
        assertTrue(attrs[OagAttributes.CONFIG_BLOCK_IP_LITERALS]!!)
    }

    @Test
    fun `startup event includes optional config fields`() {
        val event = sampleStartupEvent().copy(
            config = sampleStartupEvent().config.copy(
                policyPublicKeyPath = "/etc/oag/key.pem",
                secretFileDir = "/etc/oag/secrets",
                otelEndpoint = "http://localhost:4318",
                otelHeadersKeys = listOf("Authorization"),
                otelTimeoutMs = 5000,
                otelServiceName = "my-service"
            )
        )
        val testHarness = harness()
        testHarness.logger.log(event)
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals("/etc/oag/key.pem", attrs[OagAttributes.CONFIG_POLICY_PUBLIC_KEY_PATH])
        assertEquals("/etc/oag/secrets", attrs[OagAttributes.CONFIG_SECRET_FILE_DIR])
        assertEquals("http://localhost:4318", attrs[OagAttributes.CONFIG_OTEL_ENDPOINT])
        assertEquals(listOf("Authorization"), attrs[OagAttributes.CONFIG_OTEL_HEADERS_KEYS])
        assertEquals(5000L, attrs[OagAttributes.CONFIG_OTEL_TIMEOUT_MS])
        assertEquals("my-service", attrs[OagAttributes.CONFIG_OTEL_SERVICE_NAME])
    }

    @Test
    fun `close shuts down logger provider without error`() {
        val testHarness = harness()
        testHarness.logger.close()
        testHarness.logger.close()
    }

    @Test
    fun `otel config enabled returns false for NONE`() {
        assertFalse(OtelConfig(exporter = OtelExporterType.NONE).enabled)
    }

    @Test
    fun `otel config enabled returns true for STDOUT`() {
        assertTrue(OtelConfig(exporter = OtelExporterType.STDOUT).enabled)
    }

    @Test
    fun `otel exporter type from parses known types`() {
        assertEquals(OtelExporterType.NONE, OtelExporterType.from("none"))
        assertEquals(OtelExporterType.STDOUT, OtelExporterType.from("stdout"))
        assertEquals(OtelExporterType.OTLP_HTTP, OtelExporterType.from("otlp_http"))
        assertEquals(OtelExporterType.OTLP_GRPC, OtelExporterType.from("otlp_grpc"))
        assertEquals(OtelExporterType.STDOUT, OtelExporterType.from("STDOUT"))
    }

    @Test
    fun `otel exporter type from returns null for unknown`() {
        assertNull(OtelExporterType.from("unknown"))
        assertNull(OtelExporterType.from(null))
    }

    @Test
    fun `log handles trace with invalid trace flags gracefully`() {
        val trace = AuditTrace(
            traceId = "0af7651916cd43dd8448eb211c80319c",
            spanId = "b7ad6b7169203331",
            traceFlags = "zz"
        )
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(trace = trace))
        assertEquals(1, testHarness.exporter.finishedLogRecordItems.size)
    }

    @Test
    fun `log handles trace with null flags`() {
        val trace = AuditTrace(
            traceId = "0af7651916cd43dd8448eb211c80319c",
            spanId = "b7ad6b7169203331",
            traceFlags = null
        )
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(trace = trace))
        assertEquals(1, testHarness.exporter.finishedLogRecordItems.size)
    }

    @Test
    fun `log handles trace with empty flags string`() {
        val trace = AuditTrace(
            traceId = "0af7651916cd43dd8448eb211c80319c",
            spanId = "b7ad6b7169203331",
            traceFlags = ""
        )
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(trace = trace))
        assertEquals(1, testHarness.exporter.finishedLogRecordItems.size)
    }

    @Test
    fun `log propagates valid trace context to record`() {
        val trace = AuditTrace(
            traceId = "0af7651916cd43dd8448eb211c80319c",
            spanId = "b7ad6b7169203331",
            traceFlags = "01"
        )
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(trace = trace))
        val record = testHarness.exporter.finishedLogRecordItems[0]
        val spanContext = record.spanContext
        assertEquals("0af7651916cd43dd8448eb211c80319c", spanContext.traceId)
        assertEquals("b7ad6b7169203331", spanContext.spanId)
        assertTrue(spanContext.traceFlags.isSampled)
    }

    @Test
    fun `log propagates unsampled trace flags`() {
        val trace = AuditTrace(
            traceId = "0af7651916cd43dd8448eb211c80319c",
            spanId = "b7ad6b7169203331",
            traceFlags = "00"
        )
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(trace = trace))
        val record = testHarness.exporter.finishedLogRecordItems[0]
        assertFalse(record.spanContext.traceFlags.isSampled)
    }

    @Test
    fun `request event with null response omits response attributes`() {
        val event = AuditEvent(
            oagVersion = "0.0.0-test",
            policyHash = "abc123",
            agentId = "agent-1",
            sessionId = "session-1",
            trace = null,
            request = AuditRequest(
                host = "api.example.com",
                port = 443,
                scheme = "https",
                method = "POST",
                path = "/v1/chat",
                bytesOut = 100,
                resolvedIps = emptyList()
            ),
            response = null,
            decision = AuditDecision(action = "deny", ruleId = null, reasonCode = "no_match_default_deny"),
            secrets = AuditSecrets(
                injectionAttempted = false,
                injected = false,
                secretIds = emptyList(),
                secretVersions = emptyMap()
            ),
            redirectChain = emptyList(),
            errors = emptyList()
        )
        val testHarness = harness()
        testHarness.logger.log(event)
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertNull(attrs[OagAttributes.HTTP_RESPONSE_STATUS_CODE])
        assertNull(attrs[OagAttributes.RESPONSE_BYTES_IN])
    }

    @Test
    fun `request event includes multiple redirect hops`() {
        val hops = listOf(
            AuditRedirectHop(301, "https://a.example.com/p1", "a.example.com", 443, "https", "/p1"),
            AuditRedirectHop(302, "https://b.example.com/p2", "b.example.com", 443, "https", "/p2")
        )
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(redirectChain = hops))
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals(2L, attrs[OagAttributes.REDIRECT_COUNT])
        assertEquals(
            listOf("https://a.example.com/p1", "https://b.example.com/p2"),
            attrs[OagAttributes.REDIRECT_LOCATIONS]
        )
    }

    @Test
    fun `request event includes multiple errors`() {
        val errors = listOf(
            AuditError(code = "timeout", message = "connect timed out"),
            AuditError(code = "dns_error", message = "resolution failed")
        )
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(errors = errors))
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals(
            listOf("timeout:connect timed out", "dns_error:resolution failed"),
            attrs[OagAttributes.ERRORS]
        )
    }

    @Test
    fun `request event with secret ids but no versions omits versions array`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent(secretIds = listOf("KEY1"), secretVersions = emptyMap()))
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertEquals(listOf("KEY1"), attrs[OagAttributes.SECRETS_IDS])
        assertNull(attrs[OagAttributes.SECRETS_VERSIONS])
    }

    @Test
    fun `startup event omits optional fields when null`() {
        val event = AuditStartupEvent(
            oagVersion = "0.0.0-test",
            policyHash = "abc123",
            agentId = null,
            sessionId = null,
            config = sampleStartupEvent().config.copy(
                policyPublicKeyPath = null,
                logPath = null,
                secretFileDir = null,
                otelEndpoint = null,
                otelHeadersKeys = emptyList(),
                otelTimeoutMs = null,
                otelServiceName = null
            )
        )
        val testHarness = harness()
        testHarness.logger.log(event)
        val attrs = testHarness.exporter.finishedLogRecordItems[0].attributes
        assertNull(attrs[OagAttributes.AGENT_ID])
        assertNull(attrs[OagAttributes.SESSION_ID])
        assertNull(attrs[OagAttributes.CONFIG_POLICY_PUBLIC_KEY_PATH])
        assertNull(attrs[OagAttributes.CONFIG_LOG_PATH])
        assertNull(attrs[OagAttributes.CONFIG_SECRET_FILE_DIR])
        assertNull(attrs[OagAttributes.CONFIG_OTEL_ENDPOINT])
        assertNull(attrs[OagAttributes.CONFIG_OTEL_TIMEOUT_MS])
        assertNull(attrs[OagAttributes.CONFIG_OTEL_SERVICE_NAME])
    }

    @Test
    fun `otel config enabled returns true for OTLP_HTTP`() {
        assertTrue(OtelConfig(exporter = OtelExporterType.OTLP_HTTP, endpoint = "http://localhost:4318").enabled)
    }

    @Test
    fun `otel config enabled returns true for OTLP_GRPC`() {
        assertTrue(OtelConfig(exporter = OtelExporterType.OTLP_GRPC, endpoint = "http://localhost:4317").enabled)
    }

    @Test
    fun `multiple events emitted in sequence are all recorded`() {
        val testHarness = harness()
        testHarness.logger.log(sampleEvent())
        testHarness.logger.log(sampleToolEvent())
        testHarness.logger.log(sampleStartupEvent())
        assertEquals(3, testHarness.exporter.finishedLogRecordItems.size)
        @Suppress("DEPRECATION")
        assertEquals(OagAttributes.BODY_REQUEST, testHarness.exporter.finishedLogRecordItems[0].body.asString())
        @Suppress("DEPRECATION")
        assertEquals(OagAttributes.BODY_TOOL, testHarness.exporter.finishedLogRecordItems[1].body.asString())
        @Suppress("DEPRECATION")
        assertEquals(OagAttributes.BODY_STARTUP, testHarness.exporter.finishedLogRecordItems[2].body.asString())
    }
}
