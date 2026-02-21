package com.mustafadakhel.oag.proxy

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

import java.nio.file.Files
import java.nio.file.Path

class ComponentFactoryTest {
    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
    }

    @Test
    fun `buildComponents produces wired components without starting servers`() {
        val config = ProxyConfig(
            policy = ProxyPolicyConfig(path = tempPolicyPath())
        )
        val components = buildComponents(config)

        assertNotNull(components.debugLogger)
        assertNotNull(components.auditLogger)
        assertNotNull(components.policyService)
        assertNotNull(components.oagMetrics)
        assertNotNull(components.circuitBreakerRegistry)
        assertNotNull(components.rateLimiterRegistry)
        assertNotNull(components.secretMaterializer)
        assertNotNull(components.handler)
        assertNotNull(components.handlerConfig)
    }

    @Test
    fun `buildComponents with sessionId creates session request tracker`() {
        val config = ProxyConfig(
            policy = ProxyPolicyConfig(path = tempPolicyPath()),
            identity = ProxyIdentityConfig(sessionId = "test-session")
        )
        val components = buildComponents(config)

        assertNotNull(components.sessionRequestTracker)
    }

    @Test
    fun `buildComponents without sessionId has null session request tracker`() {
        val config = ProxyConfig(
            policy = ProxyPolicyConfig(path = tempPolicyPath())
        )
        val components = buildComponents(config)

        assertNull(components.sessionRequestTracker)
    }

    @Test
    fun `buildComponents without tls has null ca bundle and host certificate cache`() {
        val config = ProxyConfig(
            policy = ProxyPolicyConfig(path = tempPolicyPath())
        )
        val components = buildComponents(config)

        assertNull(components.caBundle)
        assertNull(components.hostCertificateCache)
        assertNull(components.sslServerSocketFactory)
    }

    @Test
    fun `buildComponents without webhook has null webhook sender`() {
        val config = ProxyConfig(
            policy = ProxyPolicyConfig(path = tempPolicyPath())
        )
        val components = buildComponents(config)

        assertNull(components.webhookSender)
        assertNull(components.webhookScope)
        assertNull(components.webhookCallback)
    }

    private fun tempPolicyPath(): String {
        val file = Files.createTempFile("policy", ".yaml")
        tempFiles.add(file)
        Files.writeString(
            file,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        return file.toString()
    }
}
