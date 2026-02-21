package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.enforcement.SessionRequestTracker
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.pipeline.denyPhase

class VelocitySpikePhase(
    private val sessionRequestTracker: SessionRequestTracker
) : GatePhase {
    override val name = "velocity_spike"
    override val stage = PipelineStage.IDENTITY

    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> {
        val sessionId = context.config.params.sessionId ?: return PhaseOutcome.Continue(Unit)
        sessionRequestTracker.record(sessionId, context.target.host, null)
        val threshold = context.config.velocitySpikeThreshold
        if (threshold <= 0.0) return PhaseOutcome.Continue(Unit)
        val velocity = sessionRequestTracker.velocity(sessionId, threshold)
        if (!velocity.spikeDetected) return PhaseOutcome.Continue(Unit)
        context.debugLog { "velocity spike detected session=$sessionId rps=${velocity.sessionRequestsPerSecond}" }
        return context.denyPhase(ReasonCode.VELOCITY_SPIKE_DETECTED, HttpStatus.TOO_MANY_REQUESTS)
    }
}
