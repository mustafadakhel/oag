package com.mustafadakhel.oag.audit

import kotlinx.serialization.json.Json

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

import java.io.ByteArrayOutputStream

class ToolAuditAdapterTest {
    private val testJson = Json { ignoreUnknownKeys = true }

    @Test
    fun `tool call logs keys and redacts values by default`() {
        val out = ByteArrayOutputStream()
        val adapter = ToolAuditAdapter(AuditLogger(out))

        adapter.logToolCall(
            ToolCallInput(
                name = "web.search",
                parameters = mapOf(
                    "query" to "weather today",
                    "api_key" to "secret-value"
                ),
                responseBytes = 128,
                durationMs = 25,
                errorCode = null,
                oagVersion = "0.1.0",
                policyHash = "abc"
            )
        )

        val event = parseFirstLine(out)
        assertEquals(AUDIT_SCHEMA_VERSION, event.schemaVersion)
        assertEquals("web.search", event.tool.name)
        assertEquals("[REDACTED]", event.tool.parameters["query"])
        assertEquals("[REDACTED]", event.tool.parameters["api_key"])
        assertEquals(2, event.tool.parameterKeys.size)
    }

    @Test
    fun `allowlisted keys are preserved unless sensitive`() {
        val out = ByteArrayOutputStream()
        val adapter = ToolAuditAdapter(
            auditLogger = AuditLogger(out),
            allowlist = setOf("query", "api_key")
        )

        adapter.logToolCall(
            ToolCallInput(
                name = "web.search",
                parameters = mapOf(
                    "query" to "kotlin style",
                    "api_key" to "secret-value"
                ),
                oagVersion = "0.1.0"
            )
        )

        val event = parseFirstLine(out)
        assertEquals("kotlin style", event.tool.parameters["query"])
        assertEquals("[REDACTED]", event.tool.parameters["api_key"])
        assertTrue("query" in event.tool.parameterKeys)
        assertTrue("api_key" in event.tool.parameterKeys)
    }

    @Test
    fun `allowlist matching is case insensitive while sensitive keys remain redacted`() {
        val out = ByteArrayOutputStream()
        val adapter = ToolAuditAdapter(
            auditLogger = AuditLogger(out),
            allowlist = setOf("Query", "traceId")
        )

        adapter.logToolCall(
            ToolCallInput(
                name = "web.search",
                parameters = mapOf(
                    "query" to "kotlin",
                    "TRACEID" to "abc-123",
                    "AuthToken" to "sensitive"
                ),
                oagVersion = "0.1.0"
            )
        )

        val event = parseFirstLine(out)
        assertEquals("kotlin", event.tool.parameters["query"])
        assertEquals("abc-123", event.tool.parameters["TRACEID"])
        assertEquals("[REDACTED]", event.tool.parameters["AuthToken"])
    }

    @Test
    fun `sensitive key patterns are redacted across common variants`() {
        val out = ByteArrayOutputStream()
        val adapter = ToolAuditAdapter(
            auditLogger = AuditLogger(out),
            allowlist = setOf("trace_id", "api-key")
        )

        adapter.logToolCall(
            ToolCallInput(
                name = "web.search",
                parameters = mapOf(
                    "trace_id" to "trace-123",
                    "api-key" to "secret-value",
                    "password" to "super-secret"
                ),
                oagVersion = "0.1.0"
            )
        )

        val event = parseFirstLine(out)
        assertEquals("trace-123", event.tool.parameters["trace_id"])
        assertEquals("[REDACTED]", event.tool.parameters["api-key"])
        assertEquals("[REDACTED]", event.tool.parameters["password"])
    }

    @Test
    fun `allowlisted values are truncated to avoid oversized logs`() {
        val out = ByteArrayOutputStream()
        val adapter = ToolAuditAdapter(
            auditLogger = AuditLogger(out),
            allowlist = setOf("query")
        )
        val longValue = "a".repeat(400)

        adapter.logToolCall(
            ToolCallInput(
                name = "web.search",
                parameters = mapOf("query" to longValue),
                oagVersion = "0.1.0"
            )
        )

        val event = parseFirstLine(out)
        assertEquals(256, event.tool.parameters["query"]!!.length)
    }

    @Test
    fun `allowlisted values are sanitized to ascii`() {
        val out = ByteArrayOutputStream()
        val adapter = ToolAuditAdapter(
            auditLogger = AuditLogger(out),
            allowlist = setOf("query")
        )

        adapter.logToolCall(
            ToolCallInput(
                name = "web.search",
                parameters = mapOf("query" to "caf\u00E9"),
                oagVersion = "0.1.0"
            )
        )

        val event = parseFirstLine(out)
        assertEquals("caf?", event.tool.parameters["query"])
    }

    @Test
    fun `parameter keys are normalized to safe ascii`() {
        val out = ByteArrayOutputStream()
        val adapter = ToolAuditAdapter(
            auditLogger = AuditLogger(out),
            allowlist = setOf("weird?key")
        )

        adapter.logToolCall(
            ToolCallInput(
                name = "web.search",
                parameters = mapOf("weird\u0001key" to "ok"),
                oagVersion = "0.1.0"
            )
        )

        val event = parseFirstLine(out)
        assertTrue("weird?key" in event.tool.parameterKeys)
    }

    @Test
    fun `allowlist normalization handles control characters`() {
        val out = ByteArrayOutputStream()
        val adapter = ToolAuditAdapter(
            auditLogger = AuditLogger(out),
            allowlist = setOf("trace\u0001id")
        )

        adapter.logToolCall(
            ToolCallInput(
                name = "web.search",
                parameters = mapOf("trace\u0001id" to "trace-123"),
                oagVersion = "0.1.0"
            )
        )

        val event = parseFirstLine(out)
        assertEquals("trace-123", event.tool.parameters["trace?id"])
    }

    private fun parseFirstLine(out: ByteArrayOutputStream): AuditToolEvent =
        testJson.decodeFromString<AuditToolEvent>(out.toString(Charsets.UTF_8).lineSequence().first { it.isNotBlank() })
}
