package com.mustafadakhel.oag

import java.net.URI

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class SafeOutboundClientTest {

    private val client = SafeOutboundClient()

    @Test
    fun `validateTarget blocks IP literal hosts`() {
        val result = client.validateTarget(URI("https://192.168.1.1/path"))
        assertIs<OutboundResult.Blocked>(result)
        assert("IP literal" in result.reason)
    }

    @Test
    fun `validateTarget blocks IPv6 literal hosts`() {
        val result = client.validateTarget(URI("https://[::1]/path"))
        assertIs<OutboundResult.Blocked>(result)
        assert("IP literal" in result.reason)
    }

    @Test
    fun `validateTarget blocks loopback resolution`() {
        val result = client.validateTarget(URI("https://localhost/path"))
        assertIs<OutboundResult.Blocked>(result)
        assert("special-purpose" in result.reason)
    }

    @Test
    fun `validateTarget returns failure for unresolvable host`() {
        val result = client.validateTarget(URI("https://this-domain-does-not-exist-oag-test.invalid/path"))
        assertIs<OutboundResult.Failure>(result)
    }

    @Test
    fun `validateTarget blocks URL with no host`() {
        val result = client.validateTarget(URI("file:///etc/passwd"))
        assertIs<OutboundResult.Blocked>(result)
        assertEquals("URL has no host", result.reason)
    }

    @Test
    fun `OutboundResult sealed interface has three variants`() {
        val success: OutboundResult<String> = OutboundResult.Success("ok")
        val failure: OutboundResult<String> = OutboundResult.Failure(RuntimeException("err"))
        val blocked: OutboundResult<String> = OutboundResult.Blocked("reason")

        assertIs<OutboundResult.Success<String>>(success)
        assertEquals("ok", success.value)
        assertIs<OutboundResult.Failure>(failure)
        assertIs<OutboundResult.Blocked>(blocked)
        assertEquals("reason", blocked.reason)
    }
}
