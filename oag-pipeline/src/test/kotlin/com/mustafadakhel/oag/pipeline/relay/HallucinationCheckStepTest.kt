package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.policy.core.HallucinationMode
import com.mustafadakhel.oag.policy.core.PolicyHallucinationCheck

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HallucinationCheckStepTest {

    private fun context() = BufferedInspectionContext(
        statusCode = 200,
        contentType = "application/json",
        matchedRule = null,
        onError = {}
    )

    @Test
    fun `step returns Continue with unmodified body`() {
        val step = HallucinationCheckStep(PolicyHallucinationCheck(enabled = true))
        val ctx = context()
        val outcome = step.inspect("response body", ctx)
        assertIs<StepOutcome.Continue>(outcome)
        assertEquals("response body", outcome.bodyText)
    }

    @Test
    fun `step writes default observe mode to accumulator`() {
        val step = HallucinationCheckStep(PolicyHallucinationCheck(enabled = true))
        val ctx = context()
        step.inspect("body", ctx)
        assertEquals("observe", ctx.accumulator.hallucinationMode)
    }

    @Test
    fun `step writes explicit enforce mode to accumulator`() {
        val step = HallucinationCheckStep(
            PolicyHallucinationCheck(enabled = true, mode = HallucinationMode.ENFORCE)
        )
        val ctx = context()
        step.inspect("body", ctx)
        assertEquals("enforce", ctx.accumulator.hallucinationMode)
    }

    @Test
    fun `step with claim matcher populates hallucination fields in accumulator`() {
        val yaml = "versions:\n  contains:\n    - \"Python 4.\""
        val matcher = ImpossibleClaimMatcher.load(yaml)
        val step = HallucinationCheckStep(
            PolicyHallucinationCheck(enabled = true, mode = HallucinationMode.ENFORCE),
            claimMatcher = matcher
        )
        val ctx = context()
        step.inspect("Use Python 4.1 for this", ctx)
        assertEquals("enforce", ctx.accumulator.hallucinationMode)
        assertNotNull(ctx.accumulator.hallucinationScore)
        assertNotNull(ctx.accumulator.hallucinationSignals)
        assertTrue(ctx.accumulator.hallucinationSignals!!.isNotEmpty())
        assertEquals("impossible_claims", ctx.accumulator.hallucinationSignals!!.first().name)
    }

    @Test
    fun `step writes empty signals to accumulator`() {
        val step = HallucinationCheckStep(PolicyHallucinationCheck(enabled = true))
        val ctx = context()
        step.inspect("body", ctx)
        assertNotNull(ctx.accumulator.hallucinationSignals)
        assertEquals(emptyList(), ctx.accumulator.hallucinationSignals)
        assertNull(ctx.accumulator.hallucinationScore)
    }
}
