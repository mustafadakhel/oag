package com.mustafadakhel.oag.policy.lifecycle

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.validation.PolicyValidationException

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

import java.nio.file.Files
import java.nio.file.Path

class PolicyLoaderTest {
    private val tempFiles = mutableListOf<Path>()
    private val tempDirs = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
        tempDirs.forEach { dir ->
            runCatching {
                Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
        tempDirs.clear()
    }

    private fun tempPolicy(): Path =
        Files.createTempFile("policy", ".yaml").also { tempFiles.add(it) }

    private fun tempDir(prefix: String): Path =
        Files.createTempDirectory(prefix).also { tempDirs.add(it) }

    @Test
    fun `unknown fields fail validation`() {
        val policyText = """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: a
                host: api.example.com
                methods: [GET]
                paths: [/]
                unexpected: true
        """.trimIndent()

        val path = tempPolicy()
        Files.writeString(path, policyText)

        assertFailsWith<Exception> {
            loadPolicy(path)
        }
    }

    @Test
    fun `load and validate rejects invalid policy`() {
        val policyText = """
            version: 2
        """.trimIndent()

        val path = tempPolicy()
        Files.writeString(path, policyText)

        assertFailsWith<PolicyValidationException> {
            loadAndValidatePolicy(path)
        }
    }

    @Test
    fun `conditions are deserialized from yaml`() {
        val policyText = """
            version: 1
            defaults:
              action: deny
            allow:
              - id: secure
                host: api.example.com
                methods: [POST]
                paths: [/v1/*]
                conditions:
                  scheme: https
                  ports: [443, 8443]
        """.trimIndent()

        val path = tempPolicy()
        Files.writeString(path, policyText)

        val policy = loadAndValidatePolicy(path)
        val rule = requireNotNull(policy.allow).first()
        val cond = requireNotNull(rule.conditions)

        assertEquals("https", cond.scheme)
        assertEquals(listOf(443, 8443), cond.ports)
    }

    @Test
    fun `reason code is deserialized from yaml`() {
        val policyText = """
            version: 1
            defaults:
              action: deny
            allow:
              - id: custom
                host: api.example.com
                reason_code: approved_by_team
        """.trimIndent()

        val path = tempPolicy()
        Files.writeString(path, policyText)

        val policy = loadAndValidatePolicy(path)
        val rule = requireNotNull(policy.allow).first()

        assertEquals("approved_by_team", rule.reasonCode)
    }

    @Test
    fun `rate limit is deserialized from yaml`() {
        val policyText = """
            version: 1
            defaults:
              action: deny
            allow:
              - id: rate_limited
                host: api.example.com
                rate_limit:
                  requests_per_second: 10.5
                  burst: 20
        """.trimIndent()

        val path = tempPolicy()
        Files.writeString(path, policyText)

        val policy = loadAndValidatePolicy(path)
        val rule = requireNotNull(policy.allow).first()
        val rl = requireNotNull(rule.rateLimit)

        assertEquals(10.5, rl.requestsPerSecond)
        assertEquals(20, rl.burst)
    }

    @Test
    fun `body match is deserialized from yaml`() {
        val policyText = """
            version: 1
            defaults:
              action: deny
            allow:
              - id: body_check
                host: api.example.com
                body_match:
                  contains: ["model", "gpt"]
                  patterns: ["gpt-\\d+"]
        """.trimIndent()

        val path = tempPolicy()
        Files.writeString(path, policyText)

        val policy = loadAndValidatePolicy(path)
        val rule = requireNotNull(policy.allow).first()
        val bm = requireNotNull(rule.bodyMatch)

        assertEquals(listOf("model", "gpt"), bm.contains)
        assertEquals(listOf("gpt-\\d+"), bm.patterns)
    }

    @Test
    fun `enum values are case insensitive`() {
        val policyText = """
            version: 1
            defaults:
              action: deny
        """.trimIndent()

        val path = tempPolicy()
        Files.writeString(path, policyText)

        val policy = loadPolicy(path)
        assertEquals(PolicyAction.DENY, policy.defaults?.action)
    }

    @Test
    fun `resolveIncludes merges allow rules from included file`() {
        val dir = tempDir("policy-includes")
        val includedPath = dir.resolve("extra.yaml")
        Files.writeString(includedPath, """
            version: 1
            allow:
              - id: included_rule
                host: included.example.com
                methods: [GET]
                paths: [/]
        """.trimIndent())

        val mainPath = dir.resolve("main.yaml")
        Files.writeString(mainPath, """
            version: 1
            includes:
              - extra.yaml
            allow:
              - id: main_rule
                host: main.example.com
                methods: [POST]
                paths: [/api/*]
        """.trimIndent())

        val resolved = resolveIncludes(mainPath)
        assertEquals(null, resolved.includes)
        assertEquals(2, resolved.allow?.size)
        assertEquals("main_rule", resolved.allow?.get(0)?.id)
        assertEquals("included_rule", resolved.allow?.get(1)?.id)
    }

    @Test
    fun `resolveIncludes merges deny rules from included file`() {
        val dir = tempDir("policy-includes")
        val includedPath = dir.resolve("deny-rules.yaml")
        Files.writeString(includedPath, """
            version: 1
            deny:
              - id: deny_included
                host: evil.example.com
        """.trimIndent())

        val mainPath = dir.resolve("main.yaml")
        Files.writeString(mainPath, """
            version: 1
            includes:
              - deny-rules.yaml
            defaults:
              action: DENY
        """.trimIndent())

        val resolved = resolveIncludes(mainPath)
        assertEquals(1, resolved.deny?.size)
        assertEquals("deny_included", resolved.deny?.first()?.id)
    }

    @Test
    fun `resolveIncludes detects circular includes`() {
        val dir = tempDir("policy-cycle")
        val aPath = dir.resolve("a.yaml")
        val bPath = dir.resolve("b.yaml")
        Files.writeString(aPath, """
            version: 1
            includes:
              - b.yaml
        """.trimIndent())
        Files.writeString(bPath, """
            version: 1
            includes:
              - a.yaml
        """.trimIndent())

        assertFailsWith<PolicyIncludeException> {
            resolveIncludes(aPath)
        }
    }

    @Test
    fun `resolveIncludes fails on missing included file`() {
        val dir = tempDir("policy-missing")
        val mainPath = dir.resolve("main.yaml")
        Files.writeString(mainPath, """
            version: 1
            includes:
              - nonexistent.yaml
        """.trimIndent())

        assertFailsWith<PolicyIncludeException> {
            resolveIncludes(mainPath)
        }
    }

    @Test
    fun `resolveIncludes enforces max depth`() {
        val dir = tempDir("policy-depth")
        Files.writeString(dir.resolve("d.yaml"), """
            version: 1
            includes:
              - e.yaml
        """.trimIndent())
        Files.writeString(dir.resolve("e.yaml"), """
            version: 1
        """.trimIndent())
        Files.writeString(dir.resolve("c.yaml"), """
            version: 1
            includes:
              - d.yaml
        """.trimIndent())
        Files.writeString(dir.resolve("b.yaml"), """
            version: 1
            includes:
              - c.yaml
        """.trimIndent())
        Files.writeString(dir.resolve("a.yaml"), """
            version: 1
            includes:
              - b.yaml
        """.trimIndent())
        val mainPath = dir.resolve("main.yaml")
        Files.writeString(mainPath, """
            version: 1
            includes:
              - a.yaml
        """.trimIndent())

        assertFailsWith<PolicyIncludeException> {
            resolveIncludes(mainPath)
        }
    }

    @Test
    fun `loadPolicy follows symlink to real policy file`() {
        val realFile = tempPolicy()
        Files.writeString(realFile, "version: 1\ndefaults:\n  action: deny\n")
        val dir = tempDir("symlink-test")
        val symlink = dir.resolve("policy-link.yaml")
        Files.createSymbolicLink(symlink, realFile)
        tempFiles.add(symlink)

        val policy = loadPolicy(symlink)
        assertEquals(PolicyAction.DENY, policy.defaults?.action)
    }

    @Test
    fun `loadAndValidatePolicy follows symlink`() {
        val realFile = tempPolicy()
        Files.writeString(realFile, "version: 1\ndefaults:\n  action: allow\n")
        val dir = tempDir("symlink-test")
        val symlink = dir.resolve("policy-link.yaml")
        Files.createSymbolicLink(symlink, realFile)
        tempFiles.add(symlink)

        val policy = loadAndValidatePolicy(symlink)
        assertEquals(PolicyAction.ALLOW, policy.defaults?.action)
    }
}
