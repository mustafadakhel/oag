package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.proxy.tls.HostCertificateCache
import com.mustafadakhel.oag.proxy.tls.generateCaBundle

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class HostCertificateCacheTest {

    private val caBundle = generateCaBundle()

    @Test
    fun `generates host certificate for hostname`() {
        val cache = HostCertificateCache(caBundle)
        val hostCert = cache.getOrCreate("api.example.com")

        assertNotNull(hostCert.certificate)
        assertNotNull(hostCert.keyPair)
        assertEquals("RSA", hostCert.keyPair.public.algorithm)
    }

    @Test
    fun `host certificate has correct CN`() {
        val cache = HostCertificateCache(caBundle)
        val hostCert = cache.getOrCreate("api.example.com")

        val subject = hostCert.certificate.subjectX500Principal.name
        assertTrue(subject.contains("CN=api.example.com"), "Subject should contain hostname CN, got: $subject")
    }

    @Test
    fun `host certificate is signed by CA`() {
        val cache = HostCertificateCache(caBundle)
        val hostCert = cache.getOrCreate("api.example.com")

        hostCert.certificate.verify(caBundle.keyPair.public)
    }

    @Test
    fun `host certificate has SAN with hostname`() {
        val cache = HostCertificateCache(caBundle)
        val hostCert = cache.getOrCreate("api.example.com")

        val sans = hostCert.certificate.subjectAlternativeNames
        assertNotNull(sans, "Host certificate should have SANs")
        val dnsNames = sans.filter { it[0] == 2 }.map { it[1] as String }
        assertTrue("api.example.com" in dnsNames, "SANs should contain hostname, got: $dnsNames")
    }

    @Test
    fun `host certificate is not a CA`() {
        val cache = HostCertificateCache(caBundle)
        val hostCert = cache.getOrCreate("api.example.com")

        val basicConstraints = hostCert.certificate.basicConstraints
        assertEquals(-1, basicConstraints, "Host certificate should not be a CA")
    }

    @Test
    fun `host certificate has digitalSignature and keyEncipherment`() {
        val cache = HostCertificateCache(caBundle)
        val hostCert = cache.getOrCreate("api.example.com")

        val keyUsage = hostCert.certificate.keyUsage
        assertNotNull(keyUsage, "Host certificate should have key usage")
        assertTrue(keyUsage[0], "digitalSignature bit should be set")
        assertTrue(keyUsage[2], "keyEncipherment bit should be set")
    }

    @Test
    fun `returns cached certificate on second call`() {
        val cache = HostCertificateCache(caBundle)
        val first = cache.getOrCreate("api.example.com")
        val second = cache.getOrCreate("api.example.com")

        assertEquals(
            first.certificate.serialNumber,
            second.certificate.serialNumber,
            "Second call should return cached certificate"
        )
    }

    @Test
    fun `different hostnames get different certificates`() {
        val cache = HostCertificateCache(caBundle)
        val cert1 = cache.getOrCreate("api.example.com")
        val cert2 = cache.getOrCreate("api.other.com")

        assertNotEquals(
            cert1.certificate.serialNumber,
            cert2.certificate.serialNumber,
            "Different hostnames should get different certificates"
        )
    }

    @Test
    fun `cache size tracks entries`() {
        val cache = HostCertificateCache(caBundle)
        assertEquals(0, cache.size)

        cache.getOrCreate("a.example.com")
        assertEquals(1, cache.size)

        cache.getOrCreate("b.example.com")
        assertEquals(2, cache.size)
    }

    @Test
    fun `evict removes hostname from cache`() {
        val cache = HostCertificateCache(caBundle)
        cache.getOrCreate("api.example.com")
        assertEquals(1, cache.size)

        cache.evict("api.example.com")
        assertEquals(0, cache.size)
    }

    @Test
    fun `clear removes all entries`() {
        val cache = HostCertificateCache(caBundle)
        cache.getOrCreate("a.example.com")
        cache.getOrCreate("b.example.com")
        assertEquals(2, cache.size)

        cache.clear()
        assertEquals(0, cache.size)
    }

    @Test
    fun `eviction triggers when cache is full`() {
        val cache = HostCertificateCache(caBundle, maxCacheSize = 2)
        cache.getOrCreate("a.example.com")
        cache.getOrCreate("b.example.com")
        assertEquals(2, cache.size)

        cache.getOrCreate("c.example.com")
        assertEquals(2, cache.size, "Cache should evict to stay within max size")
    }

    @Test
    fun `evicted hostname generates fresh certificate`() {
        val cache = HostCertificateCache(caBundle)
        val first = cache.getOrCreate("api.example.com")
        cache.evict("api.example.com")
        val second = cache.getOrCreate("api.example.com")

        assertNotEquals(
            first.certificate.serialNumber,
            second.certificate.serialNumber,
            "After eviction, a fresh certificate should be generated"
        )
    }
}
