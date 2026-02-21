package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.proxy.lifecycle.IntegrityChecker
import com.mustafadakhel.oag.proxy.lifecycle.IntegrityStatus
import com.mustafadakhel.oag.proxy.lifecycle.computeConfigFingerprint

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

import java.nio.file.Files
import java.nio.file.Path

class IntegrityCheckerTest {
    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
    }

    private fun tempPolicy(): Path {
        val path = Files.createTempFile("test-policy", ".yaml")
        path.toFile().writeText("version: 1\ndefaults:\n  action: DENY\n")
        tempFiles.add(path)
        return path
    }

    private fun createTestPolicyService(): PolicyService {
        val policyFile = tempPolicy()
        return PolicyService(policyPath = policyFile)
    }

    @Test
    fun `check returns pass when policy hash has not changed`() {
        val policyService = createTestPolicyService()
        val currentHash = policyService.currentHash
        val checker = IntegrityChecker(
            policyService = policyService,
            expectedPolicyHash = currentHash,
            initialConfigFingerprint = "fingerprint"
        )

        val result = checker.checkWithFingerprint("fingerprint")

        assertEquals(IntegrityStatus.PASS, result.status)
        assertTrue(result.policyHashMatch)
        assertTrue(result.configFingerprintMatch)
    }

    @Test
    fun `checkWithFingerprint returns drift_detected when policy hash has changed`() {
        val policyService = createTestPolicyService()
        val checker = IntegrityChecker(
            policyService = policyService,
            expectedPolicyHash = "stale-hash-that-does-not-match",
            initialConfigFingerprint = "fingerprint"
        )

        val result = checker.checkWithFingerprint("fingerprint")

        assertEquals(IntegrityStatus.DRIFT_DETECTED, result.status)
        assertEquals(false, result.policyHashMatch)
        assertTrue(result.configFingerprintMatch)
    }

    @Test
    fun `checkWithFingerprint returns pass when both match`() {
        val policyService = createTestPolicyService()
        val currentHash = policyService.currentHash
        val fingerprint = "config-fingerprint-abc"
        val checker = IntegrityChecker(
            policyService = policyService,
            expectedPolicyHash = currentHash,
            initialConfigFingerprint = fingerprint
        )

        val result = checker.checkWithFingerprint(fingerprint)

        assertEquals(IntegrityStatus.PASS, result.status)
        assertTrue(result.policyHashMatch)
        assertTrue(result.configFingerprintMatch)
    }

    @Test
    fun `checkWithFingerprint returns drift_detected when fingerprint does not match`() {
        val policyService = createTestPolicyService()
        val currentHash = policyService.currentHash
        val checker = IntegrityChecker(
            policyService = policyService,
            expectedPolicyHash = currentHash,
            initialConfigFingerprint = "original-fingerprint"
        )

        val result = checker.checkWithFingerprint("different-fingerprint")

        assertEquals(IntegrityStatus.DRIFT_DETECTED, result.status)
        assertTrue(result.policyHashMatch)
        assertEquals(false, result.configFingerprintMatch)
    }

    @Test
    fun `checkWithFingerprint returns drift_detected when policy hash does not match`() {
        val policyService = createTestPolicyService()
        val fingerprint = "config-fingerprint"
        val checker = IntegrityChecker(
            policyService = policyService,
            expectedPolicyHash = "wrong-hash",
            initialConfigFingerprint = fingerprint
        )

        val result = checker.checkWithFingerprint(fingerprint)

        assertEquals(IntegrityStatus.DRIFT_DETECTED, result.status)
        assertEquals(false, result.policyHashMatch)
        assertTrue(result.configFingerprintMatch)
    }

    @Test
    fun `checkWithFingerprint returns drift_detected when both do not match`() {
        val policyService = createTestPolicyService()
        val checker = IntegrityChecker(
            policyService = policyService,
            expectedPolicyHash = "wrong-hash",
            initialConfigFingerprint = "wrong-fingerprint"
        )

        val result = checker.checkWithFingerprint("different-fingerprint")

        assertEquals(IntegrityStatus.DRIFT_DETECTED, result.status)
        assertEquals(false, result.policyHashMatch)
        assertEquals(false, result.configFingerprintMatch)
    }

    @Test
    fun `computeConfigFingerprint is deterministic`() {
        val policyFile = tempPolicy()
        val config = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()))

        val fingerprint1 = computeConfigFingerprint(config)
        val fingerprint2 = computeConfigFingerprint(config)

        assertEquals(fingerprint1, fingerprint2)
    }

    @Test
    fun `computeConfigFingerprint changes when port changes`() {
        val policyFile = tempPolicy()

        val config1 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), listenPort = 8080)
        val config2 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), listenPort = 9090)

        val fingerprint1 = computeConfigFingerprint(config1)
        val fingerprint2 = computeConfigFingerprint(config2)

        assertNotEquals(fingerprint1, fingerprint2)
    }

    @Test
    fun `computeConfigFingerprint changes when dryRun changes`() {
        val policyFile = tempPolicy()

        val config1 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), dryRun = false)
        val config2 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), dryRun = true)

        val fingerprint1 = computeConfigFingerprint(config1)
        val fingerprint2 = computeConfigFingerprint(config2)

        assertNotEquals(fingerprint1, fingerprint2)
    }

    @Test
    fun `computeConfigFingerprint changes when verbose changes`() {
        val policyFile = tempPolicy()

        val config1 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), verbose = false)
        val config2 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), verbose = true)

        assertNotEquals(computeConfigFingerprint(config1), computeConfigFingerprint(config2))
    }

    @Test
    fun `computeConfigFingerprint changes when maxThreads changes`() {
        val policyFile = tempPolicy()

        val config1 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), maxThreads = 10)
        val config2 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), maxThreads = 20)

        assertNotEquals(computeConfigFingerprint(config1), computeConfigFingerprint(config2))
    }

    @Test
    fun `computeConfigFingerprint changes when admin allowedIps changes`() {
        val policyFile = tempPolicy()

        val config1 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), admin = ProxyAdminConfig(allowedIps = listOf("127.0.0.1")))
        val config2 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), admin = ProxyAdminConfig(allowedIps = listOf("10.0.0.1")))

        assertNotEquals(computeConfigFingerprint(config1), computeConfigFingerprint(config2))
    }

    @Test
    fun `computeConfigFingerprint changes when tls caCertPath changes`() {
        val policyFile = tempPolicy()

        val config1 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), tls = ProxyTlsConfig(caCertPath = null))
        val config2 = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()), tls = ProxyTlsConfig(caCertPath = "/path/to/ca.pem"))

        assertNotEquals(computeConfigFingerprint(config1), computeConfigFingerprint(config2))
    }

    @Test
    fun `computeConfigFingerprint returns 64 char hex string`() {
        val policyFile = tempPolicy()

        val config = ProxyConfig(policy = ProxyPolicyConfig(path = policyFile.toString()))
        val fingerprint = computeConfigFingerprint(config)

        assertEquals(64, fingerprint.length, "SHA-256 hex digest should be 64 characters")
        assertTrue(fingerprint.all { it in '0'..'9' || it in 'a'..'f' }, "Fingerprint should be lowercase hex")
    }
}
