package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.BodyBufferKey
import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.HandlerParams
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.PolicyEvalKey
import com.mustafadakhel.oag.pipeline.PolicyPhaseResult
import com.mustafadakhel.oag.pipeline.RequestContext
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.SecurityConfig
import com.mustafadakhel.oag.pipeline.relay.CountingOutputStream
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BodyMatchEvaluationTest {

    private val tempFiles = mutableListOf<Path>()

    private fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            Files.writeString(it, content)
        }

    private fun policyService(): PolicyService {
        val policy = writePolicy("version: 1\nallow:\n  - id: rule1\n    host: \"api.example.com\"\n")
        return PolicyService(policy)
    }

    private fun buildBodyContext(
        bodyText: String,
        rule: PolicyRule
    ): RequestPipelineContext {
        val bodyBytes = bodyText.toByteArray()
        val headers = mapOf(
            "host" to "api.example.com",
            HttpConstants.CONTENT_LENGTH to bodyBytes.size.toString(),
            HttpConstants.CONTENT_TYPE to "application/json"
        )
        val target = ParsedTarget(scheme = "https", host = "api.example.com", port = 443, path = "/api/v1/chat")
        val request = HttpRequest(
            method = "POST",
            target = "https://api.example.com/api/v1/chat",
            version = "HTTP/1.1",
            headers = headers
        )
        val config = HandlerConfig(
            params = HandlerParams(agentId = "agent-1", sessionId = "session-1"),
            security = SecurityConfig(agentSigningSecret = null, requireSignedHeaders = false)
        )
        val ctx = RequestPipelineContext(
            requestContext = RequestContext(config = config, target = target, request = request, trace = null),
            output = CountingOutputStream(ByteArrayOutputStream()),
            clientInput = ByteArrayInputStream(bodyBytes)
        )
        ctx.outputs.put(PolicyEvalKey, PolicyPhaseResult(
            decision = PolicyDecision(PolicyAction.ALLOW, rule.id, ReasonCode.ALLOWED_BY_RULE),
            rule = rule,
            agentProfile = null,
            tags = null
        ))
        return ctx
    }

    @Test
    fun `continues when body matches contains criteria`() {
        val rule = PolicyRule(
            host = "api.example.com",
            bodyMatch = PolicyBodyMatch(contains = listOf("hello"))
        )
        val context = buildBodyContext("""{"prompt": "hello world"}""", rule)

        val result = bufferAndMatchBodyPhase(context, policyService())

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        assertNotNull(context.outputs.getOrNull(BodyBufferKey))
    }

    @Test
    fun `denies when body does not match contains criteria`() {
        val rule = PolicyRule(
            host = "api.example.com",
            bodyMatch = PolicyBodyMatch(contains = listOf("expected_token"))
        )
        val context = buildBodyContext("""{"prompt": "goodbye world"}""", rule)

        val result = bufferAndMatchBodyPhase(context, policyService())

        assertIs<PhaseOutcome.Deny>(result)
        assertEquals(ReasonCode.BODY_MATCH_FAILED, result.decision.reasonCode)
        assertEquals(PolicyAction.DENY, result.decision.action)
    }

    @Test
    fun `denies when body does not match regex pattern`() {
        val rule = PolicyRule(
            host = "api.example.com",
            bodyMatch = PolicyBodyMatch(patterns = listOf("secret_[a-z]+_key"))
        )
        val context = buildBodyContext("""{"data": "no match here"}""", rule)

        val result = bufferAndMatchBodyPhase(context, policyService())

        assertIs<PhaseOutcome.Deny>(result)
        assertEquals(ReasonCode.BODY_MATCH_FAILED, result.decision.reasonCode)
    }

    @Test
    fun `continues when body matches regex pattern`() {
        val rule = PolicyRule(
            host = "api.example.com",
            bodyMatch = PolicyBodyMatch(patterns = listOf("secret_[a-z]+_key"))
        )
        val context = buildBodyContext("""{"key": "secret_abc_key"}""", rule)

        val result = bufferAndMatchBodyPhase(context, policyService())

        assertIs<PhaseOutcome.Continue<Unit>>(result)
    }

    @Test
    fun `continues when rule has no body match and no inspection config`() {
        val rule = PolicyRule(host = "api.example.com")
        val context = buildBodyContext("""{"prompt": "anything"}""", rule)

        val result = bufferAndMatchBodyPhase(context, policyService())

        assertIs<PhaseOutcome.Continue<Unit>>(result)
    }

    @Test
    fun `body buffer phase has correct stage and skipWhenPolicyDenied`() {
        val phase = BodyBufferPhase(policyService())

        assertEquals(PipelineStage.INSPECT, phase.stage)
        assertTrue(phase.skipWhenPolicyDenied)
    }
}
