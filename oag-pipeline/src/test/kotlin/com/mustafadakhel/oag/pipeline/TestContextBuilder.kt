package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.relay.CountingOutputStream
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.ReasonCode

import java.io.ByteArrayOutputStream

fun buildTestContext(
    host: String = "api.example.com",
    path: String = "/api/v1/chat",
    method: String = "POST",
    headers: Map<String, String> = mapOf("Host" to host, "Content-Type" to "application/json"),
    agentId: String? = "agent-1",
    sessionId: String? = "session-1",
    dryRun: Boolean = false,
    rule: PolicyRule? = null,
    policyDecision: PolicyDecision? = null,
    bodyText: String? = null,
    agentSigningSecret: String? = null
): RequestPipelineContext {
    val target = ParsedTarget(scheme = "https", host = host, port = 443, path = path)
    val request = HttpRequest(
        method = method,
        target = "https://$host$path",
        version = "HTTP/1.1",
        headers = headers
    )
    val config = HandlerConfig(
        params = HandlerParams(agentId = agentId, sessionId = sessionId, dryRun = dryRun),
        security = SecurityConfig(agentSigningSecret = agentSigningSecret, requireSignedHeaders = false)
    )
    val ctx = RequestPipelineContext(
        requestContext = RequestContext(config = config, target = target, request = request, trace = null),
        output = CountingOutputStream(ByteArrayOutputStream())
    )
    if (rule != null || policyDecision != null) {
        ctx.outputs.put(PolicyEvalKey, PolicyPhaseResult(
            decision = policyDecision ?: PolicyDecision(PolicyAction.ALLOW, rule?.id, ReasonCode.ALLOWED_BY_RULE),
            rule = rule,
            agentProfile = null,
            tags = null
        ))
    }
    if (bodyText != null) {
        ctx.outputs.put(BodyBufferKey, BodyBufferResult(
            body = bodyText.toByteArray(),
            bodyText = bodyText
        ))
    }
    return ctx
}
