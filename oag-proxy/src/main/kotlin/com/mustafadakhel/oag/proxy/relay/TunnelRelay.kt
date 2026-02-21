package com.mustafadakhel.oag.proxy.relay

import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.proxy.http.startRelay
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.RelayOutcome
import com.mustafadakhel.oag.pipeline.RequestRelay
import com.mustafadakhel.oag.pipeline.logAudit
import com.mustafadakhel.oag.pipeline.wrapUpstreamFailure
import com.mustafadakhel.oag.pipeline.relay.UpstreamConnector
import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.enforcement.recordConnectionSuccess
import com.mustafadakhel.oag.telemetry.DebugLogger

import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull

import java.io.BufferedInputStream
import java.io.BufferedOutputStream

internal fun buildTunnelRelay(
    upstreamConnector: UpstreamConnector,
    circuitBreakerRegistry: CircuitBreakerRegistry?,
    debugLogger: DebugLogger
): RequestRelay = RequestRelay { context ->
    val clientInput = requireNotNull(context.clientInput) { "clientInput must be set for CONNECT relay" }
    val effectiveReadTimeout = context.matchedRule?.readTimeoutMs ?: context.config.network.readTimeoutMs
    wrapUpstreamFailure(context.policyDecision?.ruleId, AuditExtras(tags = context.matchedTags, agentProfileId = context.agentProfileId)) {
        upstreamConnector.openSocket(
            target = context.target,
            resolvedIps = context.resolvedIps,
            ruleConnectTimeoutMs = context.matchedRule?.connectTimeoutMs,
            ruleReadTimeoutMs = context.matchedRule?.readTimeoutMs
        ).use { upstream ->
            circuitBreakerRegistry.recordConnectionSuccess(context.target.host)
            val upstreamOut = BufferedOutputStream(upstream.getOutputStream())
            val upstreamIn = BufferedInputStream(upstream.getInputStream())

            context.output.write(HttpConstants.CONNECT_ESTABLISHED_RESPONSE)
            context.output.flush()

            coroutineScope {
                val outbound = startRelay(clientInput, upstreamOut)
                val inbound = startRelay(upstreamIn, context.output)

                withTimeoutOrNull(effectiveReadTimeout.toLong()) {
                    outbound.join()
                    inbound.join()
                }

                runCatching { upstream.shutdownInput() }.onFailure { e ->
                    debugLogger.log { "upstream shutdownInput failed: ${e.message}" }
                }
                runCatching { upstream.shutdownOutput() }.onFailure { e ->
                    debugLogger.log { "upstream shutdownOutput failed: ${e.message}" }
                }

                outbound.cancel()
                inbound.cancel()
            }

            logAudit(context, context.requirePolicyDecision(), RelayOutcome(statusCode = HttpStatus.OK.code), extras = AuditExtras(tags = context.matchedTags, agentProfileId = context.agentProfileId))
        }
    }
}
