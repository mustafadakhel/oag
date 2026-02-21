package com.mustafadakhel.oag.enforcement

import java.util.concurrent.ConcurrentHashMap

class CircuitBreakerRegistry(
    private val failureThreshold: Int = CircuitBreaker.DEFAULT_FAILURE_THRESHOLD,
    private val resetTimeoutMs: Long = CircuitBreaker.DEFAULT_RESET_TIMEOUT_MS,
    private val halfOpenSuccessThreshold: Int = CircuitBreaker.DEFAULT_HALF_OPEN_SUCCESS_THRESHOLD,
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val onStateChange: ((host: String, from: CircuitState, to: CircuitState) -> Unit)? = null
) {
    private val breakers = ConcurrentHashMap<String, CircuitBreaker>()

    fun get(host: String): CircuitBreaker {
        breakers[host]?.let { return it }
        if (breakers.size >= maxEntries) {
            evictClosed()
        }
        return breakers.computeIfAbsent(host) {
            CircuitBreaker(
                failureThreshold = failureThreshold,
                resetTimeoutMs = resetTimeoutMs,
                halfOpenSuccessThreshold = halfOpenSuccessThreshold,
                onStateChange = CircuitStateListener { from, to -> onStateChange?.invoke(host, from, to) }
            )
        }
    }

    private fun evictClosed() {
        breakers.entries.removeIf { it.value.currentState() == CircuitState.CLOSED }
    }

    companion object {
        private const val DEFAULT_MAX_ENTRIES = 1_000
    }
}

fun CircuitBreakerRegistry?.recordConnectionSuccess(host: String) =
    this?.get(host)?.recordSuccess()
