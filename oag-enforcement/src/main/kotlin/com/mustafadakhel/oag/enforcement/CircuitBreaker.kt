package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.LOG_PREFIX

import java.time.Clock
import java.util.concurrent.atomic.AtomicReference

enum class CircuitState {
    CLOSED,
    OPEN,
    HALF_OPEN
}

fun interface CircuitStateListener {
    fun onStateChange(from: CircuitState, to: CircuitState)
}

private data class StateTransition(val from: CircuitState, val to: CircuitState)

class CircuitBreaker(
    private val failureThreshold: Int = DEFAULT_FAILURE_THRESHOLD,
    private val resetTimeoutMs: Long = DEFAULT_RESET_TIMEOUT_MS,
    private val halfOpenSuccessThreshold: Int = DEFAULT_HALF_OPEN_SUCCESS_THRESHOLD,
    private val clock: Clock = Clock.systemUTC(),
    private val onStateChange: CircuitStateListener? = null,
    private val onError: (String) -> Unit = System.err::println
) {
    private data class Snapshot(
        val state: CircuitState = CircuitState.CLOSED,
        val consecutiveFailures: Int = 0,
        val consecutiveSuccesses: Int = 0,
        val lastFailureMs: Long = 0
    )

    private val ref = AtomicReference(Snapshot())

    private fun notifyStateChange(from: CircuitState, to: CircuitState) {
        runCatching { onStateChange?.onStateChange(from, to) }
            .onFailure { e -> onError("${LOG_PREFIX}circuit breaker state change listener failed $from->$to: ${e.message}") }
    }

    fun currentState(): CircuitState {
        val transition = tryAutoRecover()
        transition?.let { (from, to) -> notifyStateChange(from, to) }
        return ref.get().state
    }

    fun allowRequest(): Boolean {
        val transition = tryAutoRecover()
        transition?.let { (from, to) -> notifyStateChange(from, to) }
        return ref.get().state != CircuitState.OPEN
    }

    fun recordSuccess() {
        while (true) {
            val snapshot = ref.get()
            if (snapshot.state == CircuitState.HALF_OPEN) {
                val newSuccesses = snapshot.consecutiveSuccesses + 1
                if (newSuccesses < halfOpenSuccessThreshold) {
                    val next = snapshot.copy(consecutiveSuccesses = newSuccesses)
                    if (ref.compareAndSet(snapshot, next)) return
                    continue
                }
            }
            val next = Snapshot(state = CircuitState.CLOSED, lastFailureMs = snapshot.lastFailureMs)
            if (ref.compareAndSet(snapshot, next)) {
                if (snapshot.state != CircuitState.CLOSED) {
                    notifyStateChange(snapshot.state, CircuitState.CLOSED)
                }
                return
            }
        }
    }

    fun recordFailure() {
        while (true) {
            val snapshot = ref.get()
            val newFailures = snapshot.consecutiveFailures + 1
            val newState = if (newFailures >= failureThreshold) CircuitState.OPEN else snapshot.state
            val next = Snapshot(
                state = newState,
                consecutiveFailures = newFailures,
                consecutiveSuccesses = 0,
                lastFailureMs = clock.millis()
            )
            if (ref.compareAndSet(snapshot, next)) {
                if (snapshot.state != newState) {
                    notifyStateChange(snapshot.state, newState)
                }
                return
            }
        }
    }

    val consecutiveFailures: Int get() = ref.get().consecutiveFailures

    private fun tryAutoRecover(): StateTransition? {
        while (true) {
            val snapshot = ref.get()
            if (snapshot.state != CircuitState.OPEN) return null
            if (clock.millis() - snapshot.lastFailureMs < resetTimeoutMs) return null
            val next = snapshot.copy(state = CircuitState.HALF_OPEN)
            if (ref.compareAndSet(snapshot, next)) return StateTransition(snapshot.state, next.state)
        }
    }

    companion object {
        const val DEFAULT_FAILURE_THRESHOLD = 5
        const val DEFAULT_RESET_TIMEOUT_MS = 30_000L
        const val DEFAULT_HALF_OPEN_SUCCESS_THRESHOLD = 1
    }
}
