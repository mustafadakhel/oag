/*
 * Copyright 2026 Mustafa Dakhel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
}
