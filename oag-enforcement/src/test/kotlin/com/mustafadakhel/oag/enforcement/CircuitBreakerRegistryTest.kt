package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.enforcement.CircuitState

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class CircuitBreakerRegistryTest {

    private data class HostStateTransition(val host: String, val from: CircuitState, val to: CircuitState)

    @Test
    fun `returns same breaker for same host`() {
        val registry = CircuitBreakerRegistry()
        val first = registry.get("api.example.com")
        val second = registry.get("api.example.com")
        assertSame(first, second)
    }

    @Test
    fun `returns different breakers for different hosts`() {
        val registry = CircuitBreakerRegistry()
        val first = registry.get("api.example.com")
        val second = registry.get("api.other.com")
        assertTrue(first !== second)
    }

    @Test
    fun `uses configured threshold and timeout`() {
        val registry = CircuitBreakerRegistry(failureThreshold = 2, resetTimeoutMs = 100)
        val cb = registry.get("test.com")
        cb.recordFailure()
        assertEquals(CircuitState.CLOSED, cb.currentState())
        cb.recordFailure()
        assertEquals(CircuitState.OPEN, cb.currentState())
    }

    @Test
    fun `onStateChange callback receives host and state transition`() {
        val transitions = mutableListOf<HostStateTransition>()
        val registry = CircuitBreakerRegistry(
            failureThreshold = 1,
            onStateChange = { host, from, to -> transitions.add(HostStateTransition(host, from, to)) }
        )
        registry.get("api.example.com").recordFailure()
        assertEquals(1, transitions.size)
        assertEquals("api.example.com", transitions[0].host)
        assertEquals(CircuitState.CLOSED, transitions[0].from)
        assertEquals(CircuitState.OPEN, transitions[0].to)
    }
}
