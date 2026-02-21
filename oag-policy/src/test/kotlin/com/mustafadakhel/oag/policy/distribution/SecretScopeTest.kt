package com.mustafadakhel.oag.policy.distribution

import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

import java.nio.file.Files
import java.nio.file.Path

class SecretScopeTest {
    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
    }

    @Test
    fun `secret scope restricts allowed secrets`() {
        val policyPath = Files.createTempFile("policy", ".yaml").also { tempFiles.add(it) }
        Files.writeString(
            policyPath,
            """
            version: 1
            defaults:
              action: deny
            allow:
              - id: openai_api
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
                secrets: [OPENAI_KEY, OTHER_KEY]
            secret_scopes:
              - id: OPENAI_KEY
                hosts: [api.openai.com]
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )

        val service = PolicyService(policyPath)
        val request = PolicyRequest("https", "api.openai.com", 443, "POST", "/v1/chat")
        val allowed = service.allowedSecrets(request, listOf("OPENAI_KEY", "OTHER_KEY"))

        assertEquals(setOf("OPENAI_KEY"), allowed)
    }

    @Test
    fun `no scope matches the request returns no allowed secrets`() {
        val policyPath = Files.createTempFile("policy", ".yaml").also { tempFiles.add(it) }
        Files.writeString(
            policyPath,
            """
            version: 1
            defaults:
              action: deny
            allow:
              - id: openai_api
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
                secrets: [OPENAI_KEY]
            secret_scopes:
              - id: OPENAI_KEY
                hosts: [api.other.com]
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )

        val service = PolicyService(policyPath)
        val request = PolicyRequest("https", "api.openai.com", 443, "POST", "/v1/chat")
        val allowed = service.allowedSecrets(request, listOf("OPENAI_KEY"))

        assertTrue(allowed.isEmpty())
    }

    @Test
    fun `no secret_scopes defined allows all rule secrets`() {
        val policyPath = Files.createTempFile("policy", ".yaml").also { tempFiles.add(it) }
        Files.writeString(
            policyPath,
            """
            version: 1
            defaults:
              action: deny
            allow:
              - id: openai_api
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
                secrets: [OPENAI_KEY, OTHER_KEY]
            """.trimIndent()
        )

        val service = PolicyService(policyPath)
        val request = PolicyRequest("https", "api.openai.com", 443, "POST", "/v1/chat")
        val allowed = service.allowedSecrets(request, listOf("OPENAI_KEY", "OTHER_KEY"))

        assertEquals(setOf("OPENAI_KEY", "OTHER_KEY"), allowed)
    }

    @Test
    fun `method mismatch on scope excludes secret`() {
        val policyPath = Files.createTempFile("policy", ".yaml").also { tempFiles.add(it) }
        Files.writeString(
            policyPath,
            """
            version: 1
            defaults:
              action: deny
            allow:
              - id: openai_api
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
                secrets: [OPENAI_KEY]
            secret_scopes:
              - id: OPENAI_KEY
                hosts: [api.openai.com]
                methods: [GET]
                paths: [/v1/*]
            """.trimIndent()
        )

        val service = PolicyService(policyPath)
        val request = PolicyRequest("https", "api.openai.com", 443, "POST", "/v1/chat")
        val allowed = service.allowedSecrets(request, listOf("OPENAI_KEY"))

        assertTrue(allowed.isEmpty())
    }
}
