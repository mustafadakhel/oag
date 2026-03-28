package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyExternalJudge
import com.mustafadakhel.oag.policy.core.PolicyInjectionScoring
import com.mustafadakhel.oag.policy.core.InjectionScoringMode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.nio.file.Files
import java.nio.file.Path

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ContentInspectorJudgeTest {

    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
    }

    private fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            Files.writeString(it, content)
        }

    private fun policyServiceWithJudge(
        triggerMode: String = "always",
        onError: String = "skip",
        denyThreshold: Double = 0.5
    ): PolicyService {
        val path = writePolicy(
            "version: 1\n" +
            "defaults:\n" +
            "  action: allow\n" +
            "  content_inspection:\n" +
            "    enable_builtin_patterns: true\n" +
            "  injection_scoring:\n" +
            "    mode: score\n" +
            "    deny_threshold: 0.8\n" +
            "  external_judge:\n" +
            "    enabled: true\n" +
            "    endpoint_url: \"https://judge.example.com/api\"\n" +
            "    trigger_mode: \"$triggerMode\"\n" +
            "    on_error: \"$onError\"\n" +
            "    deny_threshold: $denyThreshold\n" +
            "allow:\n" +
            "  - id: rule_1\n" +
            "    host: \"*.example.com\"\n"
        )
        return PolicyService(path)
    }

    private fun mockJudge(score: Double, decision: JudgeDecision = JudgeDecision.ABSTAIN): JudgeInvoker =
        JudgeInvoker { JudgeResult(score = score, decision = decision, source = "mock", latencyMs = 1) }

    private fun failingJudge(): JudgeInvoker =
        JudgeInvoker { throw RuntimeException("connection refused") }

    @Test
    fun `judge always mode invokes judge`() {
        val service = policyServiceWithJudge(triggerMode = "always")
        val config = PolicyContentInspection(enableBuiltinPatterns = true)
        val result = checkContentInspection("normal text", config, service, judgeInvoker = mockJudge(0.3), judgeContext = JudgeCallContext("normal text"))
        assertNotNull(result.judge)
        assertEquals(0.3, result.judge!!.score, 0.001)
    }

    @Test
    fun `judge on_error skip continues without deny`() {
        val service = policyServiceWithJudge(onError = "skip")
        val config = PolicyContentInspection(enableBuiltinPatterns = true)
        val result = checkContentInspection("normal text", config, service, judgeInvoker = failingJudge(), judgeContext = JudgeCallContext("normal text"))
        assertNull(result.decision)
        assertNotNull(result.judge?.error)
    }

    @Test
    fun `judge on_error deny blocks on failure`() {
        val service = policyServiceWithJudge(onError = "deny")
        val config = PolicyContentInspection(enableBuiltinPatterns = true)
        val result = checkContentInspection("normal text", config, service, judgeInvoker = failingJudge(), judgeContext = JudgeCallContext("normal text"))
        assertNotNull(result.decision)
        assertEquals(PolicyAction.DENY, result.decision!!.action)
    }

    @Test
    fun `judge score above threshold triggers deny`() {
        val service = policyServiceWithJudge(denyThreshold = 0.5)
        val config = PolicyContentInspection(enableBuiltinPatterns = true)
        val result = checkContentInspection("normal text", config, service, judgeInvoker = mockJudge(0.8), judgeContext = JudgeCallContext("normal text"))
        assertNotNull(result.decision)
        assertEquals(PolicyAction.DENY, result.decision!!.action)
    }

    @Test
    fun `judge score below threshold does not deny`() {
        val service = policyServiceWithJudge(denyThreshold = 0.5)
        val config = PolicyContentInspection(enableBuiltinPatterns = true)
        val result = checkContentInspection("normal text", config, service, judgeInvoker = mockJudge(0.2), judgeContext = JudgeCallContext("normal text"))
        assertNull(result.decision)
    }

    @Test
    fun `judge DENY decision overrides score`() {
        val service = policyServiceWithJudge(denyThreshold = 0.9)
        val config = PolicyContentInspection(enableBuiltinPatterns = true)
        val result = checkContentInspection("normal text", config, service, judgeInvoker = mockJudge(0.1, JudgeDecision.DENY), judgeContext = JudgeCallContext("normal text"))
        assertNotNull(result.decision)
        assertEquals(PolicyAction.DENY, result.decision!!.action)
    }

    @Test
    fun `judge result populates all fields`() {
        val service = policyServiceWithJudge()
        val config = PolicyContentInspection(enableBuiltinPatterns = true)
        val result = checkContentInspection("text", config, service, judgeInvoker = mockJudge(0.4), judgeContext = JudgeCallContext("text"))
        assertNotNull(result.judge)
        assertEquals("mock", result.judge!!.source)
        assertEquals(1L, result.judge!!.latencyMs)
    }

    @Test
    fun `full flow - policy to judge to deny with audit-ready result`() {
        val service = policyServiceWithJudge(triggerMode = "always", denyThreshold = 0.5)
        val config = PolicyContentInspection(enableBuiltinPatterns = true)
        val ctx = JudgeCallContext(requestBody = "suspicious", host = "api.example.com", path = "/chat", method = "POST")
        val result = checkContentInspection("normal text", config, service, judgeInvoker = mockJudge(0.7, JudgeDecision.DENY), judgeContext = ctx)
        assertNotNull(result.decision)
        assertEquals(PolicyAction.DENY, result.decision!!.action)
        assertNotNull(result.judge)
        assertEquals(0.7, result.judge!!.score, 0.001)
        assertEquals(JudgeDecision.DENY, result.judge!!.decision)
        assertEquals("mock", result.judge!!.source)
        assertNull(result.judge!!.error)
    }
}
