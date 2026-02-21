package com.mustafadakhel.oag

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IdentityProviderTest {

    @Test
    fun `IdentityResult defaults to unauthenticated`() {
        val result = IdentityResult()
        assertNull(result.actorId)
        assertEquals(AuthnMethod.NONE, result.authnMethod)
        assertNull(result.certInfo)
        assertNull(result.signatureInfo)
        assertFalse(result.authenticated)
    }

    @Test
    fun `IdentityResult authenticated when method is not NONE`() {
        val result = IdentityResult(actorId = "agent-1", authnMethod = AuthnMethod.SIGNATURE)
        assertTrue(result.authenticated)
    }

    @Test
    fun `IdentityResult authenticated for CERTIFICATE method`() {
        val cert = CertInfo(subject = "CN=agent")
        val result = IdentityResult(
            actorId = "agent-1",
            authnMethod = AuthnMethod.CERTIFICATE,
            certInfo = cert
        )
        assertTrue(result.authenticated)
        assertEquals("CN=agent", result.certInfo?.subject)
    }

    @Test
    fun `IdentityResult authenticated for BEARER_TOKEN method`() {
        val result = IdentityResult(actorId = "user-1", authnMethod = AuthnMethod.BEARER_TOKEN)
        assertTrue(result.authenticated)
    }

    @Test
    fun `IdentityProvider fun interface extracts identity from headers`() {
        val provider = IdentityProvider { headers ->
            val agent = headers["X-Agent-Id"]
            if (agent != null) IdentityResult(actorId = agent, authnMethod = AuthnMethod.SIGNATURE)
            else IdentityResult()
        }

        val authenticated = provider.extract(mapOf("X-Agent-Id" to "bot-1"))
        assertEquals("bot-1", authenticated.actorId)
        assertTrue(authenticated.authenticated)

        val anonymous = provider.extract(emptyMap())
        assertNull(anonymous.actorId)
        assertFalse(anonymous.authenticated)
    }

    @Test
    fun `IdentityResult with signatureInfo stores verification status`() {
        val sig = SignatureInfo(agentId = "a1", verified = true)
        val result = IdentityResult(
            actorId = "a1",
            authnMethod = AuthnMethod.SIGNATURE,
            signatureInfo = sig
        )
        assertTrue(result.signatureInfo?.verified == true)
        assertEquals("a1", result.signatureInfo?.agentId)
    }
}
