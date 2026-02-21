package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.proxy.tls.CA_SUBJECT_DN
import com.mustafadakhel.oag.proxy.tls.generateCaBundle

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CaBundleTest {

    @Test
    fun `generates valid CA certificate with default parameters`() {
        val bundle = generateCaBundle()

        assertNotNull(bundle.certificate)
        assertNotNull(bundle.keyPair)
        assertEquals("RSA", bundle.keyPair.public.algorithm)
        assertEquals("RSA", bundle.keyPair.private.algorithm)
    }

    @Test
    fun `CA certificate has correct subject DN`() {
        val bundle = generateCaBundle()
        val subject = bundle.certificate.subjectX500Principal.name

        CA_SUBJECT_DN.split(",").forEach { rdnPart ->
            val key = rdnPart.trim().substringBefore("=")
            assertTrue(subject.contains(rdnPart.trim()), "Subject should contain $key from CA_SUBJECT_DN, got: $subject")
        }
    }

    @Test
    fun `CA certificate is self-signed`() {
        val bundle = generateCaBundle()

        assertEquals(
            bundle.certificate.subjectX500Principal,
            bundle.certificate.issuerX500Principal,
            "CA certificate should be self-signed (issuer == subject)"
        )
    }

    @Test
    fun `CA certificate verifies with its own public key`() {
        val bundle = generateCaBundle()

        bundle.certificate.verify(bundle.keyPair.public)
    }

    @Test
    fun `CA certificate has basicConstraints CA=true`() {
        val bundle = generateCaBundle()

        val basicConstraints = bundle.certificate.basicConstraints
        assertTrue(basicConstraints >= 0, "CA certificate should have basicConstraints with CA=true")
    }

    @Test
    fun `CA certificate has keyUsage for cert signing`() {
        val bundle = generateCaBundle()

        val keyUsage = bundle.certificate.keyUsage
        assertNotNull(keyUsage, "CA certificate should have key usage extension")
        assertTrue(keyUsage[5], "keyCertSign bit should be set")
        assertTrue(keyUsage[6], "cRLSign bit should be set")
    }

    @Test
    fun `CA certificate is valid now`() {
        val bundle = generateCaBundle()

        bundle.certificate.checkValidity()
    }

    @Test
    fun `custom subject DN is applied`() {
        val customDn = "CN=Test CA,O=TestOrg"
        val bundle = generateCaBundle(subjectDn = customDn)

        val subject = bundle.certificate.subjectX500Principal.name
        assertTrue(subject.contains("CN=Test CA"), "Subject should contain custom CN, got: $subject")
        assertTrue(subject.contains("O=TestOrg"), "Subject should contain custom O, got: $subject")
    }

    @Test
    fun `custom validity days affects certificate expiry`() {
        val bundle = generateCaBundle(validityDays = 30)
        val now = System.currentTimeMillis()
        val notAfter = bundle.certificate.notAfter.time

        val daysDiff = (notAfter - now) / 86_400_000L
        assertTrue(daysDiff in 29..31, "Certificate should be valid for ~30 days, got: $daysDiff")
    }

    @Test
    fun `rejects key size below 2048`() {
        assertFailsWith<IllegalArgumentException>("Should reject key size below 2048") {
            generateCaBundle(keySizeBits = 1024)
        }
    }

    @Test
    fun `rejects non-positive validity days`() {
        assertFailsWith<IllegalArgumentException>("Should reject zero validity days") {
            generateCaBundle(validityDays = 0)
        }
        assertFailsWith<IllegalArgumentException>("Should reject negative validity days") {
            generateCaBundle(validityDays = -1)
        }
    }

    @Test
    fun `each invocation produces unique certificates`() {
        val bundle1 = generateCaBundle()
        val bundle2 = generateCaBundle()

        assertTrue(
            bundle1.certificate.serialNumber != bundle2.certificate.serialNumber,
            "Each CA certificate should have a unique serial number"
        )
    }
}
