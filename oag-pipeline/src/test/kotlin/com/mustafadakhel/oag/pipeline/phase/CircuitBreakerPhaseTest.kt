package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.policy.core.ReasonCode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class CircuitBreakerPhaseTest {

    @Test
    fun `continues when no registry`() {
        val phase = CircuitBreakerPhase(null)
        val context = buildTestContext()

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
    }

    @Test
    fun `continues when circuit is closed`() {
        val registry = CircuitBreakerRegistry()
        val phase = CircuitBreakerPhase(registry)
        val context = buildTestContext()

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
    }

    @Test
    fun `stage is TARGET`() {
        val phase = CircuitBreakerPhase(null)
        assertEquals(PipelineStage.TARGET, phase.stage)
    }
}
