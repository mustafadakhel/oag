package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.enforcement.DataBudgetTracker
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.nio.file.Files
import java.nio.file.Path

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DataBudgetPhaseTest {

    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
    }

    private fun writePolicy(maxBytes: Long? = null): Path =
        Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            val defaults = if (maxBytes != null) {
                "defaults:\n  action: allow\n  max_bytes_per_host_per_session: $maxBytes"
            } else {
                "defaults:\n  action: allow"
            }
            Files.writeString(it, "version: 1\n$defaults\n")
        }

    @Test
    fun `continues when no budget configured`() {
        val policyService = PolicyService(writePolicy())
        val tracker = DataBudgetTracker()
        val context = buildTestContext()

        val result = checkDataBudgetPhase(context, policyService, tracker)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
    }

    @Test
    fun `continues when no session id`() {
        val policyService = PolicyService(writePolicy(maxBytes = 1000))
        val tracker = DataBudgetTracker()
        val context = buildTestContext(sessionId = null)

        val result = checkDataBudgetPhase(context, policyService, tracker)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
    }

    @Test
    fun `continues when within budget`() {
        val policyService = PolicyService(writePolicy(maxBytes = 10000))
        val tracker = DataBudgetTracker()
        val context = buildTestContext(
            headers = mapOf("Host" to "api.example.com", "content-length" to "100")
        )

        val result = checkDataBudgetPhase(context, policyService, tracker)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        val usedBytes = context.outputs.getOrNull(DataBudgetPhase)
        assertNotNull(usedBytes)
        assertEquals(100L, usedBytes)
    }

    @Test
    fun `denies when budget exceeded`() {
        val policyService = PolicyService(writePolicy(maxBytes = 50))
        val tracker = DataBudgetTracker()
        val context = buildTestContext(
            headers = mapOf("Host" to "api.example.com", "content-length" to "100")
        )

        val result = checkDataBudgetPhase(context, policyService, tracker)

        assertIs<PhaseOutcome.Deny>(result)
        assertEquals(ReasonCode.DATA_BUDGET_EXCEEDED, result.decision.reasonCode)
    }

    @Test
    fun `skipWhenPolicyDenied is true`() {
        val phase = DataBudgetPhase(PolicyService(writePolicy()), DataBudgetTracker())
        assertTrue(phase.skipWhenPolicyDenied)
    }
}
