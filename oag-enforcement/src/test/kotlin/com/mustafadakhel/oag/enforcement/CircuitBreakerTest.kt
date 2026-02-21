package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.enforcement.CircuitBreaker
import com.mustafadakhel.oag.enforcement.CircuitState
import com.mustafadakhel.oag.enforcement.CircuitStateListener

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

class CircuitBreakerTest {

    private data class StateTransition(val from: CircuitState, val to: CircuitState)

    @Test
    fun `starts in closed state`() {
        val cb = CircuitBreaker()
        assertEquals(CircuitState.CLOSED, cb.currentState())
        assertTrue(cb.allowRequest())
    }

    @Test
    fun `stays closed below failure threshold`() {
        val cb = CircuitBreaker(failureThreshold = 3)
        cb.recordFailure()
        cb.recordFailure()
        assertEquals(CircuitState.CLOSED, cb.currentState())
        assertTrue(cb.allowRequest())
    }

    @Test
    fun `opens after reaching failure threshold`() {
        val cb = CircuitBreaker(failureThreshold = 3)
        cb.recordFailure()
        cb.recordFailure()
        cb.recordFailure()
        assertEquals(CircuitState.OPEN, cb.currentState())
        assertFalse(cb.allowRequest())
    }

    @Test
    fun `success resets failure count and closes circuit`() {
        val cb = CircuitBreaker(failureThreshold = 3)
        cb.recordFailure()
        cb.recordFailure()
        cb.recordSuccess()
        assertEquals(0, cb.consecutiveFailures)
        assertEquals(CircuitState.CLOSED, cb.currentState())
    }

    @Test
    fun `transitions to half-open after reset timeout`() = runBlocking {
        val cb = CircuitBreaker(failureThreshold = 1, resetTimeoutMs = 20)
        cb.recordFailure()
        assertEquals(CircuitState.OPEN, cb.currentState())
        delay(100)
        assertEquals(CircuitState.HALF_OPEN, cb.currentState())
        assertTrue(cb.allowRequest())
    }

    @Test
    fun `half-open closes on success`() = runBlocking {
        val cb = CircuitBreaker(failureThreshold = 1, resetTimeoutMs = 20)
        cb.recordFailure()
        delay(100)
        assertEquals(CircuitState.HALF_OPEN, cb.currentState())
        cb.recordSuccess()
        assertEquals(CircuitState.CLOSED, cb.currentState())
    }

    @Test
    fun `half-open reopens on failure`() = runBlocking {
        val cb = CircuitBreaker(failureThreshold = 1, resetTimeoutMs = 20)
        cb.recordFailure()
        delay(100)
        assertEquals(CircuitState.HALF_OPEN, cb.currentState())
        cb.recordFailure()
        assertEquals(CircuitState.OPEN, cb.currentState())
        assertFalse(cb.allowRequest())
    }

    @Test
    fun `consecutive failures tracked correctly`() {
        val cb = CircuitBreaker(failureThreshold = 10)
        repeat(5) { cb.recordFailure() }
        assertEquals(5, cb.consecutiveFailures)
        cb.recordSuccess()
        assertEquals(0, cb.consecutiveFailures)
    }

    @Test
    fun `open circuit denies requests`() {
        val cb = CircuitBreaker(failureThreshold = 1, resetTimeoutMs = 60_000)
        cb.recordFailure()
        assertFalse(cb.allowRequest())
        assertFalse(cb.allowRequest())
    }

    @Test
    fun `callback fires on state transition to open`() {
        val transitions = mutableListOf<StateTransition>()
        val cb = CircuitBreaker(failureThreshold = 2, onStateChange = CircuitStateListener { from, to -> transitions.add(StateTransition(from, to)) })
        cb.recordFailure()
        assertTrue(transitions.isEmpty())
        cb.recordFailure()
        assertEquals(1, transitions.size)
        assertEquals(StateTransition(CircuitState.CLOSED, CircuitState.OPEN), transitions[0])
    }

    @Test
    fun `callback fires on half-open transition`() = runBlocking {
        val transitions = mutableListOf<StateTransition>()
        val cb = CircuitBreaker(failureThreshold = 1, resetTimeoutMs = 20, onStateChange = CircuitStateListener { from, to -> transitions.add(StateTransition(from, to)) })
        cb.recordFailure()
        assertEquals(1, transitions.size) // CLOSED -> OPEN
        delay(100)
        cb.currentState()
        assertEquals(2, transitions.size)
        assertEquals(StateTransition(CircuitState.OPEN, CircuitState.HALF_OPEN), transitions[1])
    }

    @Test
    fun `callback fires on recovery to closed`() = runBlocking {
        val transitions = mutableListOf<StateTransition>()
        val cb = CircuitBreaker(failureThreshold = 1, resetTimeoutMs = 20, onStateChange = CircuitStateListener { from, to -> transitions.add(StateTransition(from, to)) })
        cb.recordFailure() // CLOSED -> OPEN
        delay(100)
        cb.currentState() // OPEN -> HALF_OPEN
        cb.recordSuccess() // HALF_OPEN -> CLOSED
        assertEquals(3, transitions.size)
        assertEquals(StateTransition(CircuitState.HALF_OPEN, CircuitState.CLOSED), transitions[2])
    }

    @Test
    fun `callback does not fire when state unchanged`() {
        val transitions = mutableListOf<StateTransition>()
        val cb = CircuitBreaker(failureThreshold = 5, onStateChange = CircuitStateListener { from, to -> transitions.add(StateTransition(from, to)) })
        cb.recordSuccess() // already CLOSED
        cb.recordFailure() // still CLOSED (below threshold)
        assertTrue(transitions.isEmpty())
    }
}
