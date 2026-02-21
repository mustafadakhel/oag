package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.pipeline.HeaderState
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.SecretInjectionKey
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.secrets.SecretMaterializer
import com.mustafadakhel.oag.secrets.SecretProvider
import com.mustafadakhel.oag.secrets.SecretValue

import java.nio.file.Files
import java.nio.file.Path

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SecretInjectionPhaseTest {

    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
    }

    private fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            Files.writeString(it, content)
        }

    private val noopProvider = object : SecretProvider {
        override fun resolve(secretId: String): SecretValue? = null
    }

    @Test
    fun `continues when no secrets configured`() {
        val policy = writePolicy("""
            version: 1
            defaults:
              action: allow
        """.trimIndent())
        val policyService = PolicyService(policy)
        val materializer = SecretMaterializer(noopProvider)
        val context = buildTestContext(rule = PolicyRule(host = "api.example.com"))

        val result = injectSecretsPhase(context, policyService, materializer)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        val headerState = context.outputs.getOrNull(HeaderState)
        assertNotNull(headerState)
    }

    @Test
    fun `skipWhenPolicyDenied is true`() {
        val policy = writePolicy("version: 1\ndefaults:\n  action: deny\n")
        val phase = SecretInjectionPhase(PolicyService(policy), SecretMaterializer(noopProvider))
        assertTrue(phase.skipWhenPolicyDenied)
    }

    @Test
    fun `fallback stores empty result when policy denied`() {
        val denyDecision = PolicyDecision(PolicyAction.DENY, null, ReasonCode.DENIED_BY_RULE)
        val context = buildTestContext(policyDecision = denyDecision)
        val fallback = SecretInjectionFallbackPhase()
        fallback.mutate(context)
        val result = context.outputs.getOrNull(SecretInjectionKey)
        assertNotNull(result)
    }
}
