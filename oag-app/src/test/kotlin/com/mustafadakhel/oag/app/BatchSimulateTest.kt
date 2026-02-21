package com.mustafadakhel.oag.app

import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

import java.nio.file.Files
import java.nio.file.Path

class BatchSimulateTest {
    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
    }

    private fun writePolicy(content: String) =
        Files.createTempFile("policy", ".yaml").also { tempFiles.add(it); Files.writeString(it, content) }

    private fun writeBatch(content: String, ext: String = ".yaml") =
        Files.createTempFile("batch", ext).also { tempFiles.add(it); Files.writeString(it, content) }

    private val basicPolicy = """
        version: 1
        defaults:
          action: deny
        allow:
          - id: openai
            host: api.openai.com
            methods: [POST]
            paths: [/v1/*]
            secrets: [API_KEY]
          - id: github
            host: api.github.com
            methods: [GET]
    """.trimIndent()

    @Test
    fun `batch simulate returns correct allow and deny counts`() {
        val policyPath = writePolicy(basicPolicy)
        val batchPath = writeBatch("""
            requests:
              - name: openai-chat
                method: POST
                host: api.openai.com
                path: /v1/chat
              - name: github-api
                method: GET
                host: api.github.com
                path: /repos
              - name: evil
                method: GET
                host: evil.com
                path: /steal
        """.trimIndent())

        val policyService = PolicyService(policyPath = policyPath)
        val result = runBatchSimulate(policyService, batchPath)

        assertEquals(3, result.summary.total)
        assertEquals(2, result.summary.allowCount)
        assertEquals(1, result.summary.denyCount)
    }

    @Test
    fun `batch simulate returns per-request results`() {
        val policyPath = writePolicy(basicPolicy)
        val batchPath = writeBatch("""
            requests:
              - name: openai
                method: POST
                host: api.openai.com
                path: /v1/chat
              - name: denied
                method: GET
                host: evil.com
                path: /
        """.trimIndent())

        val policyService = PolicyService(policyPath = policyPath)
        val result = runBatchSimulate(policyService, batchPath)

        assertEquals(2, result.results.size)
        assertEquals("openai", result.results[0].name)
        assertEquals("allow", result.results[0].action)
        assertEquals("openai", result.results[0].ruleId)
        assertEquals(listOf("API_KEY"), result.results[0].eligibleSecrets)

        assertEquals("denied", result.results[1].name)
        assertEquals("deny", result.results[1].action)
        assertNull(result.results[1].ruleId)
        assertNull(result.results[1].eligibleSecrets)
    }

    @Test
    fun `batch simulate tracks rule hit counts`() {
        val policyPath = writePolicy(basicPolicy)
        val batchPath = writeBatch("""
            requests:
              - method: POST
                host: api.openai.com
                path: /v1/chat
              - method: POST
                host: api.openai.com
                path: /v1/completions
              - method: GET
                host: api.github.com
                path: /repos
              - method: GET
                host: evil.com
                path: /
        """.trimIndent())

        val policyService = PolicyService(policyPath = policyPath)
        val result = runBatchSimulate(policyService, batchPath)

        assertEquals(2, result.summary.ruleHitCounts["openai"])
        assertEquals(1, result.summary.ruleHitCounts["github"])
        assertEquals(1, result.summary.ruleHitCounts["(no rule)"])
    }

    @Test
    fun `batch simulate defaults scheme and port`() {
        val policyPath = writePolicy(basicPolicy)
        val batchPath = writeBatch("""
            requests:
              - method: POST
                host: api.openai.com
                path: /v1/chat
        """.trimIndent())

        val policyService = PolicyService(policyPath = policyPath)
        val result = runBatchSimulate(policyService, batchPath)

        assertEquals("https", result.results[0].scheme)
        assertEquals(443, result.results[0].port)
    }

    @Test
    fun `batch simulate respects explicit scheme and port`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: allow
        """.trimIndent())
        val batchPath = writeBatch("""
            requests:
              - method: GET
                host: example.com
                scheme: http
                port: 8080
                path: /api
        """.trimIndent())

        val policyService = PolicyService(policyPath = policyPath)
        val result = runBatchSimulate(policyService, batchPath)

        assertEquals("http", result.results[0].scheme)
        assertEquals(8080, result.results[0].port)
    }

    @Test
    fun `batch simulate fails on empty requests`() {
        val policyPath = writePolicy(basicPolicy)
        val batchPath = writeBatch("""
            requests: []
        """.trimIndent())

        val policyService = PolicyService(policyPath = policyPath)
        assertFailsWith<CliException> {
            runBatchSimulate(policyService, batchPath)
        }
    }

    @Test
    fun `batch simulate reads JSON input`() {
        val policyPath = writePolicy(basicPolicy)
        val batchPath = writeBatch("""
            {"requests":[{"method":"POST","host":"api.openai.com","path":"/v1/chat"}]}
        """.trimIndent(), ext = ".json")

        val policyService = PolicyService(policyPath = policyPath)
        val result = runBatchSimulate(policyService, batchPath)

        assertEquals(1, result.results.size)
        assertEquals("allow", result.results[0].action)
    }

    @Test
    fun `batch simulate name field is optional`() {
        val policyPath = writePolicy(basicPolicy)
        val batchPath = writeBatch("""
            requests:
              - method: GET
                host: evil.com
                path: /
        """.trimIndent())

        val policyService = PolicyService(policyPath = policyPath)
        val result = runBatchSimulate(policyService, batchPath)

        assertNull(result.results[0].name)
    }
}
