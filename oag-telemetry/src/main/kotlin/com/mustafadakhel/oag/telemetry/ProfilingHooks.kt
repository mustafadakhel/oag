package com.mustafadakhel.oag.telemetry

import com.mustafadakhel.oag.NS_PER_MS

data class PhaseTimings(
    val policyEvaluationNs: Long = 0,
    val dnsResolutionNs: Long = 0,
    val upstreamConnectNs: Long = 0,
    val requestRelayNs: Long = 0,
    val responseRelayNs: Long = 0,
    val secretMaterializationNs: Long = 0,
    val totalNs: Long = 0
) {
    fun toAuditMap(): Map<String, Double> = buildMap {
        fun emit(key: String, ns: Long) { if (ns > 0) put(key, ns.toDouble() / NS_PER_MS) }
        emit(AUDIT_POLICY_EVALUATION_MS, policyEvaluationNs)
        emit(AUDIT_DNS_RESOLUTION_MS, dnsResolutionNs)
        emit(AUDIT_UPSTREAM_CONNECT_MS, upstreamConnectNs)
        emit(AUDIT_REQUEST_RELAY_MS, requestRelayNs)
        emit(AUDIT_RESPONSE_RELAY_MS, responseRelayNs)
        emit(AUDIT_SECRET_MATERIALIZATION_MS, secretMaterializationNs)
        emit(AUDIT_TOTAL_MS, totalNs)
    }

    companion object {
        const val AUDIT_POLICY_EVALUATION_MS = "policy_evaluation_ms"
        const val AUDIT_DNS_RESOLUTION_MS = "dns_resolution_ms"
        const val AUDIT_UPSTREAM_CONNECT_MS = "upstream_connect_ms"
        const val AUDIT_REQUEST_RELAY_MS = "request_relay_ms"
        const val AUDIT_RESPONSE_RELAY_MS = "response_relay_ms"
        const val AUDIT_SECRET_MATERIALIZATION_MS = "secret_materialization_ms"
        const val AUDIT_TOTAL_MS = "total_ms"
    }
}

class RequestProfiler {
    @PublishedApi
    internal val phases = mutableMapOf<String, Long>()
    private val startTime = System.nanoTime()

    inline fun <T> measure(phase: String, block: () -> T): T {
        val phaseStart = System.nanoTime()
        return try {
            block()
        } finally {
            phases[phase] = System.nanoTime() - phaseStart
        }
    }

    fun finish(): PhaseTimings = PhaseTimings(
        policyEvaluationNs = phases[PHASE_POLICY_EVALUATION] ?: 0,
        dnsResolutionNs = phases[PHASE_DNS_RESOLUTION] ?: 0,
        upstreamConnectNs = phases[PHASE_UPSTREAM_CONNECT] ?: 0,
        requestRelayNs = phases[PHASE_REQUEST_RELAY] ?: 0,
        responseRelayNs = phases[PHASE_RESPONSE_RELAY] ?: 0,
        secretMaterializationNs = phases[PHASE_SECRET_MATERIALIZATION] ?: 0,
        totalNs = System.nanoTime() - startTime
    )

    companion object {
        const val PHASE_POLICY_EVALUATION = "policy_evaluation"
        const val PHASE_DNS_RESOLUTION = "dns_resolution"
        const val PHASE_UPSTREAM_CONNECT = "upstream_connect"
        const val PHASE_REQUEST_RELAY = "request_relay"
        const val PHASE_RESPONSE_RELAY = "response_relay"
        const val PHASE_SECRET_MATERIALIZATION = "secret_materialization"
    }
}
