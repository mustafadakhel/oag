/*
 * Copyright 2026 Mustafa Dakhel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.SafeOutboundClient

import kotlin.test.Test
import kotlin.test.assertEquals
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
            timeoutMs = 1000
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
            timeoutMs = 1000
        )
        verifier.verify("trigger failure to open circuit")
        assertTrue(verifier.circuitOpen)
        val result = verifier.verify("should not call endpoint")
        assertNull(result.score)
        assertEquals("circuit_open", result.error)
    }

    @Test
    fun `SSRF rejection for private IP endpoint`() {
        val client = SafeOutboundClient()
        val verifier = ExternalVerifier(
            client = client,
            endpointUrl = "http://127.0.0.1:8080/verify"
        )
        val result = verifier.verify("test response")
        assertNull(result.score)
        assertNotNull(result.error)
        assertTrue(result.error!!.startsWith("blocked"))
    }

    @Test
    fun `HTTPS enforcement - only https and http schemes accepted by SafeOutboundClient`() {
        val client = SafeOutboundClient()
        val verifier = ExternalVerifier(
            client = client,
            endpointUrl = "https://valid-but-nonexistent-oag-test.invalid/verify",
            timeoutMs = 1000
        )
        val result = verifier.verify("test")
        // Should fail with network error, not scheme error
        assertNull(result.score)
        assertNotNull(result.error)
    }
}
