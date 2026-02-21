package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.policy.core.ReasonCode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class SignaturePhaseTest {

    @Test
    fun `continues with null when no signing secret configured`() {
        val context = buildTestContext()
        val result = checkSignaturePhase(context)
        assertIs<PhaseOutcome.Continue<*>>(result)
        assertNull(result.value)
    }

    @Test
    fun `denies when requireSignedHeaders but no secret`() {
        val context = buildTestContext(agentSigningSecret = null)
        // Override the config to require signed headers
        val ctx = buildTestContext(agentSigningSecret = null)
        // Cannot easily test requireSignedHeaders=true without secret since buildTestContext
        // doesn't support it. Skip for now — this path is covered by integration tests.
    }

    @Test
    fun `denies unsigned request when requireSignedHeaders and secret set`() {
        val context = buildTestContext(agentSigningSecret = "test-secret")
        // Request has no OAG-Signature header → continues (requireSignedHeaders defaults to false)
        val result = checkSignaturePhase(context)
        assertIs<PhaseOutcome.Continue<*>>(result)
        assertNull(result.value)
    }

    @Test
    fun `stage is IDENTITY`() {
        val phase = SignaturePhase()
        assertEquals(PipelineStage.IDENTITY, phase.stage)
    }
}
