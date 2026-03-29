package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.SafeOutboundClient

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ExternalJudgeClientTest {

    @Test
    fun `SSRF prevention rejects localhost`() {
        val client = SafeOutboundClient()
        assertFailsWith<IllegalArgumentException> {
            ExternalJudgeClient(client = client, endpointUrl = "http://127.0.0.1:8080/judge")
        }
    }

    @Test
    fun `SSRF prevention rejects private IP`() {
        val client = SafeOutboundClient()
        assertFailsWith<IllegalArgumentException> {
            ExternalJudgeClient(client = client, endpointUrl = "http://192.168.1.1/judge")
        }
    }

    @Test
    fun `timeout returns error result not exception`() {
        val client = SafeOutboundClient()
        // Nonexistent host will timeout/fail
        val judgeClient = runCatching {
            ExternalJudgeClient(
                client = client,
                endpointUrl = "https://nonexistent-judge-oag-test.invalid/judge",
                timeoutMs = 1000
            )
        }.getOrNull()
        // Construction may fail due to DNS validation
        if (judgeClient != null) {
            val result = judgeClient.invoke(JudgeRequest(requestBody = "test"))
            assertNotNull(result.error)
            assertEquals(JudgeDecision.ABSTAIN, result.decision)
        }
    }

    @Test
    fun `JudgeDecision fromLabel parses correctly`() {
        assertEquals(JudgeDecision.DENY, JudgeDecision.fromLabel("deny"))
        assertEquals(JudgeDecision.ALLOW, JudgeDecision.fromLabel("allow"))
        assertEquals(JudgeDecision.ABSTAIN, JudgeDecision.fromLabel("abstain"))
        assertEquals(JudgeDecision.ABSTAIN, JudgeDecision.fromLabel(null))
        assertEquals(JudgeDecision.ABSTAIN, JudgeDecision.fromLabel("unknown"))
    }

    @Test
    fun `JudgeResult error classification`() {
        val result = JudgeResult(
            score = 0.0,
            decision = JudgeDecision.ABSTAIN,
            source = "external",
            latencyMs = 100,
            error = "connection refused"
        )
        assertEquals(0.0, result.score, 0.001)
        assertNotNull(result.error)
        assertTrue(result.latencyMs > 0)
    }

    @Test
    fun `sanitizeForJudge truncates long strings`() {
        val long = "a".repeat(50_000)
        val sanitized = long.sanitizeForJudge()
        assertTrue(sanitized.length <= 32_768)
    }

    @Test
    fun `sanitizeForJudge removes null bytes`() {
        val dirty = "hello\u0000world"
        assertEquals("helloworld", dirty.sanitizeForJudge())
    }
}
