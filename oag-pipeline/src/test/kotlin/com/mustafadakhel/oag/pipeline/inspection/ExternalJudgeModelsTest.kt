package com.mustafadakhel.oag.pipeline.inspection

import kotlinx.serialization.json.Json

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ExternalJudgeModelsTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `JudgeRequest serialization round-trip`() {
        val request = JudgeRequest(requestBody = "test body", host = "api.example.com", method = "POST")
        val encoded = json.encodeToString(request)
        val decoded = json.decodeFromString<JudgeRequest>(encoded)
        assertEquals(request, decoded)
    }

    @Test
    fun `JudgeResponse deserialization`() {
        val responseJson = """{"score": 0.85, "decision": "deny", "reason": "suspicious"}"""
        val response = json.decodeFromString<JudgeResponse>(responseJson)
        assertEquals(0.85, response.score, 0.001)
        assertEquals("deny", response.decision)
        assertEquals("suspicious", response.reason)
    }

    @Test
    fun `JudgeResponse with minimal fields`() {
        val responseJson = """{"score": 0.3}"""
        val response = json.decodeFromString<JudgeResponse>(responseJson)
        assertEquals(0.3, response.score, 0.001)
        assertEquals(null, response.decision)
    }

    @Test
    fun `sanitizeForJudge truncates`() {
        val long = "x".repeat(50_000)
        assertTrue(long.sanitizeForJudge().length <= 32_768)
    }

    @Test
    fun `sanitizeForJudge strips null bytes`() {
        assertEquals("ab", "a\u0000b".sanitizeForJudge())
    }

    @Test
    fun `sanitizeForJudge custom max length`() {
        assertEquals("abc", "abcdef".sanitizeForJudge(maxLength = 3))
    }

    @Test
    fun `JudgeDecision fromLabel`() {
        assertEquals(JudgeDecision.DENY, JudgeDecision.fromLabel("deny"))
        assertEquals(JudgeDecision.DENY, JudgeDecision.fromLabel("DENY"))
        assertEquals(JudgeDecision.ALLOW, JudgeDecision.fromLabel("allow"))
        assertEquals(JudgeDecision.ABSTAIN, JudgeDecision.fromLabel("abstain"))
        assertEquals(JudgeDecision.ABSTAIN, JudgeDecision.fromLabel(null))
        assertEquals(JudgeDecision.ABSTAIN, JudgeDecision.fromLabel("unknown"))
    }

    @Test
    fun `JudgeResult score bounds`() {
        val result = JudgeResult(score = 0.95, decision = JudgeDecision.DENY, source = "external", latencyMs = 42)
        assertEquals(0.95, result.score, 0.001)
        assertEquals("external", result.source)
        assertEquals(42L, result.latencyMs)
    }

    @Test
    fun `JudgeCallContext carries request metadata`() {
        val ctx = JudgeCallContext(
            requestBody = "body",
            host = "api.example.com",
            path = "/chat",
            method = "POST",
            injectionScore = 0.6
        )
        assertEquals("api.example.com", ctx.host)
        assertEquals(0.6, ctx.injectionScore!!, 0.001)
    }

    @Test
    fun `JudgeInvoker is a fun interface`() {
        val invoker = JudgeInvoker { ctx ->
            JudgeResult(score = 0.5, decision = JudgeDecision.ALLOW, source = "mock", latencyMs = 1)
        }
        val result = invoker.invoke(JudgeCallContext(requestBody = "test"))
        assertEquals(0.5, result.score, 0.001)
    }
}
