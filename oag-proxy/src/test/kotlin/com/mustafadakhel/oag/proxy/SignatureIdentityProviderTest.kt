package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.AuthnMethod
import com.mustafadakhel.oag.computeHmacSha256
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.phase.signatureIdentityProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SignatureIdentityProviderTest {

    private val secret = "test-secret"
    private val method = "GET"
    private val host = "api.example.com"
    private val path = "/v1/chat"

    private fun validHeaders(agentId: String? = "agent-1"): Map<String, String> {
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val canonical = "$method\n$host\n$path\n$timestamp"
        val hmac = computeHmacSha256(secret, canonical.toByteArray(Charsets.UTF_8))
        return buildMap {
            put(HttpConstants.OAG_SIGNATURE, "hmac-sha256=$hmac")
            put(HttpConstants.OAG_TIMESTAMP, timestamp)
            if (agentId != null) put(HttpConstants.OAG_AGENT_ID, agentId)
        }
    }

    @Test
    fun `returns authenticated identity for valid signature`() {
        val provider = signatureIdentityProvider(secret, method, host, path)
        val result = provider.extract(validHeaders())
        assertTrue(result.authenticated)
        assertEquals("agent-1", result.actorId)
        assertEquals(AuthnMethod.SIGNATURE, result.authnMethod)
        assertTrue(result.signatureInfo?.verified == true)
        assertEquals("agent-1", result.signatureInfo?.agentId)
    }

    @Test
    fun `returns unauthenticated for missing signature header`() {
        val provider = signatureIdentityProvider(secret, method, host, path)
        val result = provider.extract(emptyMap())
        assertFalse(result.authenticated)
        assertNull(result.actorId)
        assertEquals(AuthnMethod.NONE, result.authnMethod)
    }

    @Test
    fun `returns unauthenticated for invalid signature`() {
        val provider = signatureIdentityProvider(secret, method, host, path)
        val headers = mapOf(
            HttpConstants.OAG_SIGNATURE to "hmac-sha256=deadbeef",
            HttpConstants.OAG_TIMESTAMP to (System.currentTimeMillis() / 1000).toString()
        )
        val result = provider.extract(headers)
        assertFalse(result.authenticated)
        assertNull(result.actorId)
    }

    @Test
    fun `returns unauthenticated for expired timestamp`() {
        val provider = signatureIdentityProvider(secret, method, host, path)
        val oldTimestamp = "1000000"
        val canonical = "$method\n$host\n$path\n$oldTimestamp"
        val hmac = computeHmacSha256(secret, canonical.toByteArray(Charsets.UTF_8))
        val headers = mapOf(
            HttpConstants.OAG_SIGNATURE to "hmac-sha256=$hmac",
            HttpConstants.OAG_TIMESTAMP to oldTimestamp
        )
        val result = provider.extract(headers)
        assertFalse(result.authenticated)
    }

    @Test
    fun `valid signature without agent id sets null actorId`() {
        val provider = signatureIdentityProvider(secret, method, host, path)
        val result = provider.extract(validHeaders(agentId = null))
        assertTrue(result.authenticated)
        assertNull(result.actorId)
        assertEquals(AuthnMethod.SIGNATURE, result.authnMethod)
        assertNull(result.signatureInfo)
    }

    @Test
    fun `different secrets produce different results`() {
        val provider1 = signatureIdentityProvider(secret, method, host, path)
        val provider2 = signatureIdentityProvider("other-secret", method, host, path)
        val headers = validHeaders()
        assertTrue(provider1.extract(headers).authenticated)
        assertFalse(provider2.extract(headers).authenticated)
    }

    @Test
    fun `different request contexts produce different results`() {
        val provider = signatureIdentityProvider(secret, "POST", host, path)
        val headers = validHeaders()
        assertFalse(provider.extract(headers).authenticated)
    }
}
