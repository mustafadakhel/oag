package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.enforcement.SessionRequestTracker
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.HandlerParams
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.RequestContext
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.SecurityConfig
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.pipeline.relay.CountingOutputStream
import com.mustafadakhel.oag.policy.core.ReasonCode
import java.io.ByteArrayOutputStream
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class VelocitySpikePhaseTest {

    @Test
    fun `continues when no session id`() {
        val tracker = SessionRequestTracker()
        val phase = VelocitySpikePhase(tracker)
        val context = buildTestContext(sessionId = null)

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
    }

    @Test
    fun `continues when threshold is zero`() {
        val tracker = SessionRequestTracker()
        val phase = VelocitySpikePhase(tracker)
        val context = buildTestContext()

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
    }

    @Test
    fun `stage is IDENTITY`() {
        val phase = VelocitySpikePhase(SessionRequestTracker())
        assertEquals(PipelineStage.IDENTITY, phase.stage)
    }

    @Test
    fun `denies with VELOCITY_SPIKE_DETECTED when spike detected`() {
        val clock = Clock.fixed(Instant.parse("2025-01-01T00:00:00Z"), ZoneOffset.UTC)
        val tracker = SessionRequestTracker(velocityWindowMs = 60_000, clock = clock)
        val phase = VelocitySpikePhase(tracker)

        // Pre-load enough requests to trigger a spike at threshold 1.0 rps
        repeat(100) { tracker.record("session-1", "api.example.com", null) }

        val context = buildSpikeContext(velocitySpikeThreshold = 1.0)
        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Deny>(result)
        assertEquals(ReasonCode.VELOCITY_SPIKE_DETECTED, result.decision.reasonCode)
    }

    private fun buildSpikeContext(velocitySpikeThreshold: Double): RequestPipelineContext {
        val target = ParsedTarget(scheme = "https", host = "api.example.com", port = 443, path = "/api")
        val request = HttpRequest(method = "GET", target = "https://api.example.com/api", version = "HTTP/1.1", headers = mapOf("host" to "api.example.com"))
        val config = HandlerConfig(
            params = HandlerParams(agentId = "agent-1", sessionId = "session-1"),
            security = SecurityConfig(agentSigningSecret = null, requireSignedHeaders = false),
            velocitySpikeThreshold = velocitySpikeThreshold
        )
        return RequestPipelineContext(
            requestContext = RequestContext(config = config, target = target, request = request, trace = null),
            output = CountingOutputStream(ByteArrayOutputStream())
        )
    }
}
