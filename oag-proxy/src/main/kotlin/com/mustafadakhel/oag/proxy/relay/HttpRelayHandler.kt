package com.mustafadakhel.oag.proxy.relay

import com.mustafadakhel.oag.NS_PER_MS
import com.mustafadakhel.oag.audit.AuditResponseRewrite
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.buildUpstreamRequestHead
import com.mustafadakhel.oag.pipeline.OagRequestException
import com.mustafadakhel.oag.pipeline.RelayOutcome
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.RequestRelay
import com.mustafadakhel.oag.pipeline.inspection.RequestBodyException
import com.mustafadakhel.oag.pipeline.inspection.ResponseRelayResult
import com.mustafadakhel.oag.pipeline.inspection.resolveContentInspection
import com.mustafadakhel.oag.pipeline.inspection.resolveDataClassification
import com.mustafadakhel.oag.pipeline.readLine
import com.mustafadakhel.oag.pipeline.phase.parseStatusCode
import com.mustafadakhel.oag.pipeline.logAudit
import com.mustafadakhel.oag.pipeline.relay.UpstreamConnector
import com.mustafadakhel.oag.pipeline.relay.forwardRequestBody
import com.mustafadakhel.oag.pipeline.relay.ResponseRelayer
import com.mustafadakhel.oag.pipeline.relay.toRetryPolicy
import com.mustafadakhel.oag.proxy.ProxyDefaults
import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.enforcement.ConnectionPool
import com.mustafadakhel.oag.enforcement.recordConnectionSuccess
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.proxy.websocket.relayWebSocketSession
import com.mustafadakhel.oag.telemetry.DebugLogger
import com.mustafadakhel.oag.telemetry.OagMetrics
import com.mustafadakhel.oag.telemetry.RequestProfiler

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.Socket

private data class UpstreamConnection(val socket: Socket, val retryCount: Int, val pooled: Boolean)

private sealed class WebSocketUpgradeOutcome {
    data object Upgraded : WebSocketUpgradeOutcome()
    data class FallbackToHttp(val consumedStatusLine: String) : WebSocketUpgradeOutcome()
    data object NotUpgrade : WebSocketUpgradeOutcome()
}

internal class HttpRelayHandler(
    private val policyService: PolicyService,
    private val responseRelayer: ResponseRelayer,
    private val debugLogger: DebugLogger,
    private val upstreamConnector: UpstreamConnector,
    private val connectionPool: ConnectionPool?,
    private val circuitBreakerRegistry: CircuitBreakerRegistry?,
    private val tokenBudgetTracker: TokenBudgetTracker,
    private val detectorRegistry: DetectorRegistry = DetectorRegistry.empty(),
    private val metrics: OagMetrics? = null
) : RequestRelay {
    override suspend fun relay(context: RequestPipelineContext) {
        val clientInput = requireNotNull(context.clientInput) { "clientInput must be set before relay" }
        context.requirePolicyDecision()

        var connection: UpstreamConnection? = null
        var releaseToPool = false
        try {
            connection = acquireUpstreamConnection(context)
            val upstreamOut = BufferedOutputStream(connection.socket.getOutputStream())
            val upstreamIn = BufferedInputStream(connection.socket.getInputStream())

            upstreamOut.write(buildUpstreamRequestHead(context).toByteArray(Charsets.US_ASCII))
            val bytesOut = context.profiler.measure(RequestProfiler.PHASE_REQUEST_RELAY) {
                forwardRequestBody(context.request, clientInput, upstreamOut, context.bufferedBody)
            }
            upstreamOut.flush()

            val preReadStatusLine = if (detectWebSocketUpgrade(context.request)) {
                when (val outcome = tryWebSocketUpgrade(context, upstreamIn, upstreamOut, bytesOut)) {
                    is WebSocketUpgradeOutcome.Upgraded -> return
                    is WebSocketUpgradeOutcome.FallbackToHttp -> outcome.consumedStatusLine
                    WebSocketUpgradeOutcome.NotUpgrade -> null
                }
            } else null

            val responseRewriteAuditEntries = mutableListOf<AuditResponseRewrite>()
            val relayResult = context.profiler.measure(RequestProfiler.PHASE_RESPONSE_RELAY) {
                responseRelayer.relay(
                    upstreamIn = upstreamIn, clientOutput = context.output,
                    request = context.request, requestTarget = context.target,
                    matchedRule = context.matchedRule,
                    responseRewriteAuditCollector = responseRewriteAuditEntries,
                    preReadStatusLine = preReadStatusLine
                )
            }

            releaseToPool = relayResult.connectionReusable && connectionPool != null
            recordRelayResult(context, relayResult, bytesOut, connection.retryCount, responseRewriteAuditEntries)
        } catch (e: Exception) {
            handleRelayError(context, e, connection?.retryCount ?: 0)
        } finally {
            releaseOrCloseUpstream(connection, releaseToPool, context)
        }
    }

    private suspend fun acquireUpstreamConnection(context: RequestPipelineContext): UpstreamConnection {
        val pooled = connectionPool?.acquire(context.target.host, context.target.port)
        if (pooled != null) {
            metrics?.recordPoolHit()
            circuitBreakerRegistry.recordConnectionSuccess(context.target.host)
            debugLogger.log { "upstream reused ${context.target.host}:${context.target.port}" }
            return UpstreamConnection(socket = pooled, retryCount = 0, pooled = true)
        }
        if (connectionPool != null) metrics?.recordPoolMiss()
        val retryPolicy = context.matchedRule?.retry.toRetryPolicy(ProxyDefaults.RETRY_DELAY_MS)
        val result = context.profiler.measure(RequestProfiler.PHASE_UPSTREAM_CONNECT) {
            upstreamConnector.retryConnect(
                context.target, context.resolvedIps,
                context.matchedRule?.connectTimeoutMs, context.matchedRule?.readTimeoutMs,
                retryPolicy
            )
        }
        circuitBreakerRegistry.recordConnectionSuccess(context.target.host)
        debugLogger.log { "upstream connected ${context.target.host}:${context.target.port}" }
        return UpstreamConnection(socket = result.socket, retryCount = result.attempts, pooled = false)
    }

    private fun buildUpstreamRequestHead(context: RequestPipelineContext): String {
        val headers = context.requestSpan?.let { span ->
            context.headers + (HttpConstants.TRACEPARENT to span.traceParentHeader())
        } ?: context.headers
        return buildUpstreamRequestHead(context.request.method, context.target.path, context.request.version, headers)
    }

    private fun detectWebSocketUpgrade(request: HttpRequest): Boolean =
        request.headers[HttpConstants.CONNECTION]?.contains(HttpConstants.UPGRADE, ignoreCase = true) == true &&
            request.headers[HttpConstants.UPGRADE]?.equals(HttpConstants.UPGRADE_WEBSOCKET, ignoreCase = true) == true

    private suspend fun tryWebSocketUpgrade(
        context: RequestPipelineContext,
        upstreamIn: BufferedInputStream,
        upstreamOut: BufferedOutputStream,
        bytesOut: Long
    ): WebSocketUpgradeOutcome {
        val statusLine = readLine(upstreamIn) ?: return WebSocketUpgradeOutcome.NotUpgrade
        val statusCode = try { parseStatusCode(statusLine) } catch (_: IllegalArgumentException) { null }
        if (statusCode != HttpStatus.SWITCHING_PROTOCOLS.code) {
            return WebSocketUpgradeOutcome.FallbackToHttp(statusLine)
        }
        val wsHeaders = buildList {
            while (true) {
                val line = readLine(upstreamIn) ?: break
                if (line.isEmpty()) break
                add(line)
            }
        }
        val response101 = buildString {
            append(statusLine).append(HttpConstants.CRLF)
            wsHeaders.forEach { append(it).append(HttpConstants.CRLF) }
            append(HttpConstants.CRLF)
        }
        context.output.write(response101.toByteArray(Charsets.US_ASCII))
        context.output.flush()

        val wsResult = relayWebSocketSession(
            clientInput = requireNotNull(context.clientInput) { "clientInput required for WebSocket relay" },
            clientOutput = context.output,
            serverInput = upstreamIn, serverOutput = upstreamOut,
            contentInspection = resolveContentInspection(context.matchedRule, policyService.current.defaults),
            dataClassification = resolveDataClassification(context.matchedRule, policyService.current.defaults),
            readTimeoutMs = context.matchedRule?.readTimeoutMs ?: context.config.network.readTimeoutMs,
            detectorRegistry = detectorRegistry,
            inspectionContext = InspectionContext(
                host = context.target.host,
                method = context.request.method,
                path = context.target.path,
                ruleId = context.policyDecision?.ruleId,
                agentId = context.config.params.agentId
            ),
            onError = debugLogger::log
        )
        logAudit(
            context,
            context.requirePolicyDecision(),
            RelayOutcome(statusCode = HttpStatus.SWITCHING_PROTOCOLS.code, bytesOut = bytesOut),
            webSocketSession = wsResult.session
        )
        return WebSocketUpgradeOutcome.Upgraded
    }

    private fun recordRelayResult(
        context: RequestPipelineContext,
        relayResult: ResponseRelayResult,
        bytesOut: Long,
        retryCount: Int,
        responseRewriteAuditEntries: List<AuditResponseRewrite>
    ) {
        val policyDecision = context.requirePolicyDecision()
        val finalDecision = relayResult.decisionOverride ?: policyDecision
        debugLogger.log { "response status=${relayResult.statusCode ?: "-"} bytes_in=${relayResult.bytesIn} duration_ms=${(System.nanoTime() - context.startNs) / NS_PER_MS}" }
        context.requestSpan?.apply {
            relayResult.statusCode?.let { setAttribute("http.response.status_code", it.toLong()) }
            setAttribute("oag.decision.action", finalDecision.action.label())
            setAttribute("oag.decision.reason_code", finalDecision.effectiveReasonCode())
            if (finalDecision.action == PolicyAction.DENY) setErrorStatus()
        }
        val auditTokenUsage = recordAndBuildTokenUsage(
            relayResult = relayResult,
            sessionId = context.config.params.sessionId,
            policyService = policyService,
            tokenBudgetTracker = tokenBudgetTracker
        )
        val contentInspection = buildFinalContentInspection(context, relayResult)
        logAudit(
            context, finalDecision,
            RelayOutcome(
                statusCode = relayResult.statusCode ?: HttpStatus.BAD_GATEWAY.code,
                bytesOut = bytesOut, bytesIn = relayResult.bytesIn,
                redirectChain = relayResult.redirectChain,
                retryCount = retryCount.takeIf { it > 0 },
                responseRewrites = responseRewriteAuditEntries.ifEmpty { null },
                tokenUsage = auditTokenUsage
            ),
            structuredPayload = context.buildAuditPayload(),
            extras = AuditExtras(contentInspection = contentInspection)
        )
    }

    private fun handleRelayError(
        context: RequestPipelineContext,
        error: Exception,
        retryCount: Int
    ) {
        val ruleId = context.requirePolicyDecision().ruleId
        val extras = AuditExtras(tags = context.matchedTags, agentProfileId = context.agentProfileId)
        when (error) {
            is RequestBodyException ->
                throw OagRequestException.InvalidRequest(ruleId, extras)
            else ->
                throw OagRequestException.UpstreamFailure(ruleId, retryCount, extras)
        }
    }

    private fun releaseOrCloseUpstream(
        connection: UpstreamConnection?,
        releaseToPool: Boolean,
        context: RequestPipelineContext
    ) {
        val socket = connection?.socket ?: return
        if (releaseToPool) {
            requireNotNull(connectionPool).release(context.target.host, context.target.port, socket)
        } else {
            runCatching { socket.close() }.onFailure { e ->
                debugLogger.log { "upstream close failed: ${e.message}" }
            }
        }
    }
}
