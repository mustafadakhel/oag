package com.mustafadakhel.oag.pipeline

private const val DEFAULT_CONNECT_TIMEOUT_MS = 5_000
private const val DEFAULT_READ_TIMEOUT_MS = 30_000

data class NetworkConfig(
    val blockIpLiterals: Boolean = false,
    val blockPrivateResolvedIps: Boolean = false,
    val enforceRedirectPolicy: Boolean = false,
    val connectTimeoutMs: Int = DEFAULT_CONNECT_TIMEOUT_MS,
    val readTimeoutMs: Int = DEFAULT_READ_TIMEOUT_MS
)
