package com.mustafadakhel.oag.policy.distribution

import com.mustafadakhel.oag.policy.evaluation.hashPolicy
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.policy.lifecycle.loadAndValidatePolicy
import com.mustafadakhel.oag.policy.evaluation.normalize

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Base64

class PolicyBundleTest {
    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
    }

    @Test
    fun `policy bundle loads and verifies signature`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )
        val policy = loadAndValidatePolicy(policyPath).normalize()
        val policyHash = hashPolicy(policy)
        val keyPair = generateKeyPair()
        val signature = signPolicyHash(policyHash, keyPair.private)

        val bundle = PolicyBundle(
            bundleVersion = 1,
            createdAt = "2026-02-23T00:00:00Z",
            policy = policy,
            policyHash = policyHash,
            signing = PolicyBundleSigning(
                algorithm = "ed25519",
                keyId = "test-key",
                signature = signature
            )
        )
        val bundlePath = writeBundle(bundle)
        val publicKeyPath = writePublicKeyPem(keyPair)

        val service = PolicyService(
            policyPath = bundlePath,
            policyPublicKeyPath = publicKeyPath.toString(),
            requireSignature = true
        )

        assertEquals(policyHash, service.currentHash)
        val info = service.currentBundleInfo
        assertNotNull(info)
        assertEquals(SignatureStatus.VERIFIED, info.signatureStatus)
        assertEquals("test-key", info.signingKeyId)
    }

    @Test
    fun `policy bundle hash mismatch fails`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val policy = loadAndValidatePolicy(policyPath).normalize()
        val policyHash = hashPolicy(policy)
        val keyPair = generateKeyPair()
        val signature = signPolicyHash(policyHash, keyPair.private)

        val bundle = PolicyBundle(
            bundleVersion = 1,
            createdAt = "2026-02-23T00:00:00Z",
            policy = policy,
            policyHash = "deadbeef",
            signing = PolicyBundleSigning(
                algorithm = "ed25519",
                keyId = null,
                signature = signature
            )
        )
        val bundlePath = writeBundle(bundle)
        val publicKeyPath = writePublicKeyPem(keyPair)

        assertFailsWith<IllegalArgumentException> {
            PolicyService(
                policyPath = bundlePath,
                policyPublicKeyPath = publicKeyPath.toString(),
                requireSignature = true
            ).currentHash
        }
    }

    @Test
    fun `policy bundle signature verification fails on invalid signature`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val policy = loadAndValidatePolicy(policyPath).normalize()
        val policyHash = hashPolicy(policy)
        val keyPair = generateKeyPair()

        val bundle = PolicyBundle(
            bundleVersion = 1,
            createdAt = "2026-02-23T00:00:00Z",
            policy = policy,
            policyHash = policyHash,
            signing = PolicyBundleSigning(
                algorithm = "ed25519",
                keyId = "bad-key",
                signature = "not-a-valid-signature"
            )
        )
        val bundlePath = writeBundle(bundle)
        val publicKeyPath = writePublicKeyPem(keyPair)

        assertFailsWith<IllegalArgumentException> {
            PolicyService(
                policyPath = bundlePath,
                policyPublicKeyPath = publicKeyPath.toString(),
                requireSignature = true
            ).currentHash
        }
    }

    private fun generateKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also { tempFiles.add(it); Files.writeString(it, content) }

    private fun writeBundle(bundle: PolicyBundle): Path =
        Files.createTempFile("bundle", ".json").also { path ->
            tempFiles.add(path)
            encodeToPath(path, PolicyBundle.serializer(), bundle)
        }

    private fun writePublicKeyPem(keyPair: KeyPair): Path {
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(keyPair.public.encoded)
        val pem = buildString {
            appendLine("-----BEGIN PUBLIC KEY-----")
            appendLine(encoded)
            appendLine("-----END PUBLIC KEY-----")
        }
        return Files.createTempFile("public", ".pem").also { tempFiles.add(it); Files.writeString(it, pem) }
    }
}
