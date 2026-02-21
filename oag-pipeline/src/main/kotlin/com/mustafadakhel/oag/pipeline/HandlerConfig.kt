package com.mustafadakhel.oag.pipeline

data class HandlerParams(
    val agentId: String?,
    val sessionId: String?,
    val dryRun: Boolean = false,
    val oagVersion: String = ""
)

data class HandlerConfig(
    val security: SecurityConfig = SecurityConfig(agentSigningSecret = null, requireSignedHeaders = false),
    val network: NetworkConfig = NetworkConfig(),
    val requestId: RequestIdConfig = RequestIdConfig(),
    val params: HandlerParams,
    val velocitySpikeThreshold: Double = 0.0
)
