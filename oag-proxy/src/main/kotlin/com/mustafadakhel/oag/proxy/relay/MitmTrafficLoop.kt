package com.mustafadakhel.oag.proxy.relay

import com.mustafadakhel.oag.SCHEME_HTTPS
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker
import com.mustafadakhel.oag.pipeline.WebhookCallback
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.proxy.http.parseHttpRequest
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.ConnectFallbackData
import com.mustafadakhel.oag.pipeline.ConnectFallbackKey
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.OagRequestException
import com.mustafadakhel.oag.pipeline.Pipeline
import com.mustafadakhel.oag.pipeline.RelayOutcome
import com.mustafadakhel.oag.pipeline.RequestContext
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.buildUpstreamRequestHead
import com.mustafadakhel.oag.pipeline.handleRequestException
import com.mustafadakhel.oag.pipeline.inspection.ResponseRelayResult
import com.mustafadakhel.oag.pipeline.logAudit
import com.mustafadakhel.oag.pipeline.relay.CountingOutputStream
import com.mustafadakhel.oag.pipeline.relay.forwardRequestBody
import com.mustafadakhel.oag.pipeline.relay.ResponseRelayer

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

internal class MitmTrafficLoop(
    private val prePolicyPipeline: Pipeline,
    private val pipeline: Pipeline,
    private val policyService: PolicyService,
    private val responseRelayer: ResponseRelayer,
    private val tokenBudgetTracker: TokenBudgetTracker,
    private val circuitBreakerRegistry: CircuitBreakerRegistry? = null,
    private val webhookCallback: WebhookCallback? = null
) : MitmTrafficHandler {
    override suspend fun run(connectContext: RequestPipelineContext, tunnel: MitmSslTunnel) =
        handleTraffic(connectContext, tunnel.clientInput, tunnel.clientOutput, tunnel.upstreamInput, tunnel.upstreamOutput)

    private suspend fun handleTraffic(
        connectContext: RequestPipelineContext,
        clientInput: InputStream,
        clientOutput: OutputStream,
        upstreamInput: InputStream,
        upstreamOutput: OutputStream
    ) {
        while (true) {
            val innerRequest = try {
                parseHttpRequest(clientInput)
            } catch (_: IllegalArgumentException) {
                return
            } catch (_: IOException) {
                return
            }
            val context = buildInnerContext(connectContext, innerRequest, clientInput, clientOutput)

            try {
                prePolicyPipeline.run(context)
                pipeline.run(context)

                val requestHead = buildUpstreamRequestHead(innerRequest.method, context.target.path, innerRequest.version, context.headers)
                upstreamOutput.write(requestHead.toByteArray(Charsets.US_ASCII))

                val bytesOut = forwardRequestBody(innerRequest, clientInput, upstreamOutput, context.bufferedBody)
                upstreamOutput.flush()

                val relayResult = responseRelayer.relay(
                    upstreamIn = upstreamInput,
                    clientOutput = context.output,
                    request = innerRequest,
                    requestTarget = context.target,
                    matchedRule = context.matchedRule
                )

                val finalDecision = relayResult.decisionOverride ?: context.requirePolicyDecision()
                auditRelayResult(context, finalDecision, relayResult, bytesOut)
                if (!shouldKeepAlive(innerRequest, relayResult, finalDecision)) return

            } catch (e: OagRequestException) {
                handleRequestException(context, e, circuitBreakerRegistry, webhookCallback)
                return
            }
        }
    }

    private fun auditRelayResult(
        context: RequestPipelineContext,
        finalDecision: PolicyDecision,
        relayResult: ResponseRelayResult,
        bytesOut: Long
    ) {
        val auditTokenUsage = recordAndBuildTokenUsage(
            relayResult = relayResult,
            sessionId = context.config.params.sessionId,
            policyService = policyService,
            tokenBudgetTracker = tokenBudgetTracker
        )
        logAudit(
            context = context,
            decision = finalDecision,
            outcome = RelayOutcome(
                statusCode = relayResult.statusCode ?: HttpStatus.BAD_GATEWAY.code,
                bytesOut = bytesOut,
                bytesIn = relayResult.bytesIn,
                redirectChain = relayResult.redirectChain,
                tokenUsage = auditTokenUsage
            ),
            structuredPayload = context.buildAuditPayload(),
            extras = AuditExtras(contentInspection = buildFinalContentInspection(context, relayResult))
        )
    }

    private fun buildInnerContext(
        connectContext: RequestPipelineContext,
        innerRequest: HttpRequest,
        clientInput: InputStream,
        clientOutput: OutputStream
    ): RequestPipelineContext {
        val innerTarget = ParsedTarget(
            scheme = SCHEME_HTTPS,
            host = connectContext.target.host,
            port = connectContext.target.port,
            path = innerRequest.target
        )
        val requestContext = RequestContext(
            config = connectContext.config,
            target = innerTarget,
            request = innerRequest,
            trace = connectContext.trace,
            policyHash = connectContext.policyHash
        )
        return RequestPipelineContext(
            requestContext = requestContext,
            output = CountingOutputStream(clientOutput),
            clientInput = clientInput,
            debugLog = connectContext.debugLog,
            emitAudit = connectContext.emitAudit
        ).also {
            it.outputs.put(ConnectFallbackKey, ConnectFallbackData(
                matchedRule = connectContext.matchedRule,
                resolvedIps = connectContext.resolvedIps
            ))
        }
    }

    private fun shouldKeepAlive(
        request: HttpRequest,
        relayResult: ResponseRelayResult,
        finalDecision: PolicyDecision
    ): Boolean {
        val clientKeepAlive = when {
            request.version == HttpConstants.HTTP_1_0 ->
                request.headers[HttpConstants.CONNECTION]?.equals(HttpConstants.CONNECTION_KEEP_ALIVE, ignoreCase = true) == true
            else ->
                request.headers[HttpConstants.CONNECTION]?.equals(HttpConstants.CONNECTION_CLOSE, ignoreCase = true) != true
        }
        return relayResult.connectionReusable && clientKeepAlive && finalDecision.action != PolicyAction.DENY
    }
}
