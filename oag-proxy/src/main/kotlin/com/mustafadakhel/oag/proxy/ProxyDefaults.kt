package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.enforcement.CircuitBreaker

object ProxyDefaults {
    const val LISTEN_HOST = "0.0.0.0"
    const val LISTEN_PORT = 8080
    const val MAX_THREADS = 32
    const val CONNECT_TIMEOUT_MS = 5_000
    const val READ_TIMEOUT_MS = 30_000
    const val DRAIN_TIMEOUT_MS = 10_000
    const val SECRET_ENV_PREFIX = "OAG_SECRET_"
    const val REQUEST_ID_HEADER = "X-Request-Id"
    val CIRCUIT_BREAKER_THRESHOLD = CircuitBreaker.DEFAULT_FAILURE_THRESHOLD
    val CIRCUIT_BREAKER_RESET_MS = CircuitBreaker.DEFAULT_RESET_TIMEOUT_MS
    val CIRCUIT_BREAKER_HALF_OPEN_PROBES = CircuitBreaker.DEFAULT_HALF_OPEN_SUCCESS_THRESHOLD
    const val POOL_IDLE_TIMEOUT_MS = 60_000
    const val WEBHOOK_TIMEOUT_MS = 5_000
    const val LOG_MAX_FILES = 5
    const val POLICY_FETCH_INTERVAL_S = 60
    const val POLICY_FETCH_TIMEOUT_MS = 10_000
    const val ADMIN_RELOAD_COOLDOWN_MS = 5_000
    const val ADMIN_LISTEN_HOST = "127.0.0.1"
    const val RETRY_DELAY_MS = 100L
    const val WS_SESSION_TIMEOUT_MS = 600_000L
    const val OAG_VERSION = "0.1.0"
}
