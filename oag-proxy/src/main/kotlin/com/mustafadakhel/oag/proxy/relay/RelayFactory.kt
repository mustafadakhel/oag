package com.mustafadakhel.oag.proxy.relay

import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.RequestRelay
import com.mustafadakhel.oag.pipeline.wrapUpstreamFailure

internal fun buildMitmRelay(
    establishTunnel: MitmTunnelEstablisher,
    handleTraffic: MitmTrafficHandler
): RequestRelay = RequestRelay { context ->
    wrapUpstreamFailure(context.policyDecision?.ruleId, AuditExtras(tags = context.matchedTags, agentProfileId = context.agentProfileId)) {
        val tunnel = establishTunnel.establish(context)
        try {
            handleTraffic.run(context, tunnel)
        } finally {
            tunnel.close()
        }
    }
}

internal fun buildConnectRelay(
    tunnelRelay: RequestRelay,
    mitmRelay: RequestRelay?
): RequestRelay = RequestRelay { context ->
    val tlsInspectRequested = context.matchedRule?.tlsInspect == true
    val mitmEnabled = tlsInspectRequested && mitmRelay != null && context.clientSocket != null
    if (tlsInspectRequested && !mitmEnabled) {
        context.debugLog { "MITM requested but not possible: mitmRelay=${mitmRelay != null} clientSocket=${context.clientSocket != null}" }
    }
    if (mitmEnabled) requireNotNull(mitmRelay).relay(context) else tunnelRelay.relay(context)
}
