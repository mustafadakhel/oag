package com.mustafadakhel.oag.policy.lifecycle

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.evaluation.hashPolicy

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

import java.nio.file.Files
import java.nio.file.Path

class PolicyServiceTest {
    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
    }

    private fun tempPolicy(): Path =
        Files.createTempFile("policy-service", ".yaml").also { tempFiles.add(it) }

    @Test
    fun `current hash matches current policy hash before and after reload`() {
        val path = tempPolicy()
        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )

        val service = PolicyService(path)
        assertEquals(hashPolicy(service.current), service.currentHash)

        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [GET]
                paths: [/v1/*]
            """.trimIndent()
        )
        service.reload()

        assertEquals(hashPolicy(service.current), service.currentHash)
    }

    @Test
    fun `reload returns changed true when policy changes`() {
        val path = tempPolicy()
        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )

        val service = PolicyService(path)
        val originalHash = service.currentHash

        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: new-rule
                host: api.example.com
                methods: [GET]
                paths: [/*]
            """.trimIndent()
        )

        val result = service.reload()
        assertEquals(originalHash, result.previousHash)
        assertTrue(result.changed)
        assertTrue(result.previousHash != result.newHash)
        assertEquals(result.newHash, service.currentHash)
    }

    @Test
    fun `reload returns changed false when policy is unchanged`() {
        val path = tempPolicy()
        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )

        val service = PolicyService(path)

        val result = service.reload()
        assertFalse(result.changed)
        assertEquals(result.previousHash, result.newHash)
    }

    @Test
    fun `policy history records initial load and changes`() {
        val path = tempPolicy()
        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )

        val service = PolicyService(path)
        val initialHash = service.currentHash

        assertEquals(1, service.policyHistory.size)
        assertEquals(initialHash, service.policyHistory.first().hash)

        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: r1
                host: api.example.com
            """.trimIndent()
        )
        service.reload()

        assertEquals(2, service.policyHistory.size)
        assertEquals(initialHash, service.policyHistory[0].hash)
        assertEquals(service.currentHash, service.policyHistory[1].hash)
    }

    @Test
    fun `policy history does not grow on unchanged reload`() {
        val path = tempPolicy()
        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )

        val service = PolicyService(path)
        service.reload()
        service.reload()

        assertEquals(1, service.policyHistory.size)
    }

    @Test
    fun `reload throws on invalid policy and keeps old snapshot`() {
        val path = tempPolicy()
        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )

        val service = PolicyService(path)
        val originalHash = service.currentHash

        Files.writeString(path, "invalid: yaml: [broken")
        assertFailsWith<Exception> { service.reload() }

        assertEquals(originalHash, service.currentHash)
        assertEquals(1, service.policyHistory.size)
    }

    @Test
    fun `reload result contains new policy document`() {
        val path = tempPolicy()
        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )

        val service = PolicyService(path)

        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: ALLOW
            """.trimIndent()
        )

        val result = service.reload()
        assertTrue(result.changed)
        assertEquals(PolicyAction.ALLOW, result.policy.defaults?.action)
    }

    @Test
    fun `currentBundleInfo is null for plain YAML policy`() {
        val path = tempPolicy()
        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [GET]
                paths: [/v1/*]
            """.trimIndent()
        )

        val service = PolicyService(path)
        assertNull(service.currentBundleInfo)
    }

    @Test
    fun `concurrent reloads are serialized`() {
        val path = tempPolicy()
        Files.writeString(
            path,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )

        val service = PolicyService(path)
        val threads = (1..8).map { i ->
            Thread {
                Files.writeString(
                    path,
                    """
                    version: 1
                    defaults:
                      action: DENY
                    allow:
                      - id: rule$i
                        host: api$i.example.com
                        methods: [GET]
                        paths: [/*]
                    """.trimIndent()
                )
                runCatching { service.reload() }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join(5000) }

        assertTrue(service.currentHash.isNotEmpty())
        assertTrue(service.policyHistory.isNotEmpty())
    }
}
