package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.PolicyEvalKey
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.nio.file.Files
import java.nio.file.Path

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

class PolicyEvalPhaseTest {

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

    @Test
    fun `allows matching host`() {
        val policy = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: rule_1
                host: "api.example.com"
        """.trimIndent())
        val policyService = PolicyService(policy)
        val phase = PolicyEvalPhase(policyService)
        val context = buildTestContext(host = "api.example.com")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        val evalResult = context.outputs.getOrNull(PolicyEvalKey)
        assertNotNull(evalResult)
        assertEquals(PolicyAction.ALLOW, evalResult.decision.action)
    }

    @Test
    fun `denies non-matching host with default deny`() {
        val policy = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: rule_1
                host: "other.example.com"
        """.trimIndent())
        val policyService = PolicyService(policy)
        val phase = PolicyEvalPhase(policyService)
        val context = buildTestContext(host = "api.example.com")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Deny>(result)
        assertEquals(PolicyAction.DENY, result.decision.action)
    }

    @Test
    fun `ip block decision takes priority over policy match`() {
        val policy = writePolicy("""
            version: 1
            defaults:
              action: allow
        """.trimIndent())
        val policyService = PolicyService(policy)
        val ipBlockDecision = PolicyDecision(PolicyAction.DENY, null, ReasonCode.RAW_IP_LITERAL_BLOCKED)
        val context = buildTestContext()

        val result = evaluatePolicyPhase(context, policyService, ipBlockDecision = ipBlockDecision, resolvedIpDecision = null)

        assertIs<PhaseOutcome.Deny>(result)
        assertEquals(ReasonCode.RAW_IP_LITERAL_BLOCKED, result.decision.reasonCode)
    }

    @Test
    fun `stores policy result in outputs`() {
        val policy = writePolicy("""
            version: 1
            defaults:
              action: allow
        """.trimIndent())
        val policyService = PolicyService(policy)
        val phase = PolicyEvalPhase(policyService)
        val context = buildTestContext()

        phase.evaluate(context)

        val evalResult = context.outputs.getOrNull(PolicyEvalKey)
        assertNotNull(evalResult)
        assertNotNull(evalResult.decision)
    }

    @Test
    fun `stage is POLICY`() {
        val policy = writePolicy("version: 1\ndefaults:\n  action: deny\n")
        val phase = PolicyEvalPhase(PolicyService(policy))
        assertEquals(com.mustafadakhel.oag.PipelineStage.POLICY, phase.stage)
    }
}
