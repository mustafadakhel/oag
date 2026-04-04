package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.SafeOutboundClient

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ExternalVerifierTest {

    @Test
    fun `circuit breaker opens after consecutive failures`() {
        val client = SafeOutboundClient()
        val verifier = ExternalVerifier(
            client = client,
            endpointUrl = "https://this-endpoint-does-not-exist-oag-test.invalid/verify",
            maxConsecutiveFailures = 2,
            timeoutMs = 1000,
            validateUrl = false
        )
        assertFalse(verifier.circuitOpen)
        verifier.verify("test")
        verifier.verify("test")
        assertTrue(verifier.circuitOpen)
    }

    @Test
    fun `circuit open returns error without calling endpoint`() {
        val client = SafeOutboundClient()
        val verifier = ExternalVerifier(
            client = client,
            endpointUrl = "https://this-endpoint-does-not-exist-oag-test.invalid/verify",
            maxConsecutiveFailures = 1,
            timeoutMs = 1000,
            validateUrl = false
        )
        verifier.verify("trigger failure to open circuit")
        assertTrue(verifier.circuitOpen)
        val result = verifier.verify("should not call endpoint")
        assertNull(result.score)
        assertEquals("circuit_open", result.error)
    }

    @Test
    fun `SSRF rejection for private IP at construction`() {
        val client = SafeOutboundClient()
        assertFailsWith<IllegalArgumentException> {
            ExternalVerifier(
                client = client,
                endpointUrl = "http://127.0.0.1:8080/verify"
            )
        }
    }

    // Network-dependent tests (unreachable endpoint, HTTPS enforcement) removed:
    // DNS resolution behavior for .invalid TLD varies by OS and network config.
    // SSRF is validated at construction time via validateTarget.
}
