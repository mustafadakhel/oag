package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.AuthnMethod
import com.mustafadakhel.oag.proxy.tls.generateCaBundle
import com.mustafadakhel.oag.proxy.tls.HostCertificateCache
import com.mustafadakhel.oag.proxy.tls.extractCertificateIdentity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CertificateIdentityProviderTest {

    private val caBundle = generateCaBundle()

    @Test
    fun `extracts identity from CA certificate CN`() {
        val result = extractCertificateIdentity(caBundle.certificate)

        assertTrue(result.authenticated)
        assertEquals(AuthnMethod.CERTIFICATE, result.authnMethod)
        assertNotNull(result.actorId)
        assertNotNull(result.certInfo)
        assertTrue(result.certInfo!!.subject.contains("CN="))
    }

    @Test
    fun `extracts SAN DNS from host certificate`() {
        val cache = HostCertificateCache(caBundle)
        val hostCert = cache.getOrCreate("agent.example.com")
        val result = extractCertificateIdentity(hostCert.certificate)

        assertTrue(result.authenticated)
        assertEquals("agent.example.com", result.actorId)
        assertEquals(AuthnMethod.CERTIFICATE, result.authnMethod)
    }

    @Test
    fun `certInfo contains subject issuer and serial`() {
        val cache = HostCertificateCache(caBundle)
        val hostCert = cache.getOrCreate("bot.internal")
        val result = extractCertificateIdentity(hostCert.certificate)

        val certInfo = result.certInfo
        assertNotNull(certInfo)
        assertTrue(certInfo.subject.contains("bot.internal"))
        assertNotNull(certInfo.issuer)
        assertNotNull(certInfo.serialNumber)
    }

    @Test
    fun `result is deterministic for same certificate`() {
        val result1 = extractCertificateIdentity(caBundle.certificate)
        val result2 = extractCertificateIdentity(caBundle.certificate)

        assertEquals(result1.actorId, result2.actorId)
        assertEquals(result1.authnMethod, result2.authnMethod)
        assertEquals(result1.certInfo?.subject, result2.certInfo?.subject)
    }

    @Test
    fun `self-signed CA cert has same subject and issuer`() {
        val result = extractCertificateIdentity(caBundle.certificate)
        val certInfo = result.certInfo!!

        assertEquals(certInfo.subject, certInfo.issuer)
    }

    @Test
    fun `host cert has different issuer than subject`() {
        val cache = HostCertificateCache(caBundle)
        val hostCert = cache.getOrCreate("service.local")
        val result = extractCertificateIdentity(hostCert.certificate)
        val certInfo = result.certInfo!!

        assertTrue(certInfo.subject != certInfo.issuer)
    }
}
