package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.denyPhase

class CircuitBreakerPhase(
    private val circuitBreakerRegistry: CircuitBreakerRegistry?
) : GatePhase {
    override val name = "circuit_breaker"
    override val stage = PipelineStage.TARGET
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkCircuitBreakerPhase(context, circuitBreakerRegistry)
}

fun checkCircuitBreakerPhase(context: RequestPipelineContext, circuitBreakerRegistry: CircuitBreakerRegistry?): PhaseOutcome<Unit> {
    val registry = circuitBreakerRegistry ?: return PhaseOutcome.Continue(Unit)
    val cb = registry.get(context.target.host)
    if (!cb.allowRequest()) {
        context.debugLog { "circuit open host=${context.target.host}" }
        return context.denyPhase(ReasonCode.CIRCUIT_OPEN, HttpStatus.SERVICE_UNAVAILABLE)
    }
    return PhaseOutcome.Continue(Unit)
}
