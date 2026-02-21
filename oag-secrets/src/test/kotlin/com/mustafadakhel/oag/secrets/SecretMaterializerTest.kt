package com.mustafadakhel.oag.secrets

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SecretMaterializerTest {
    @Test
    fun `invalid placeholder id is rejected`() {
        val materializer = SecretMaterializer(object : SecretProvider {
            override fun resolve(secretId: String): SecretValue? = SecretValue("value")
        })

        val outcome = materializer.inject(
            headers = mapOf("authorization" to "OAG_PLACEHOLDER_BAD ID"),
            allowedSecretIds = setOf("BAD ID")
        )

        assertFalse(outcome.result.injected)
        assertEquals(listOf("BAD ID"), outcome.result.attemptedIds)
        assertTrue(outcome.result.errors.any { it.startsWith("secret_invalid_id:") })
    }

    @Test
    fun `valid placeholder id is injected when allowed`() {
        val materializer = SecretMaterializer(object : SecretProvider {
            override fun resolve(secretId: String): SecretValue? = SecretValue("resolved-value", "v1")
        })

        val outcome = materializer.inject(
            headers = mapOf("authorization" to "OAG_PLACEHOLDER_OPENAI_KEY"),
            allowedSecretIds = setOf("OPENAI_KEY")
        )

        assertTrue(outcome.result.injected)
        assertEquals("resolved-value", outcome.headers["authorization"])
        assertEquals("v1", outcome.result.secretVersions["OPENAI_KEY"])
    }

    @Test
    fun `bearer placeholder is injected preserving prefix`() {
        val materializer = SecretMaterializer(object : SecretProvider {
            override fun resolve(secretId: String): SecretValue? = SecretValue("resolved-value")
        })

        val outcome = materializer.inject(
            headers = mapOf("authorization" to "Bearer OAG_PLACEHOLDER_OPENAI_KEY"),
            allowedSecretIds = setOf("OPENAI_KEY")
        )

        assertTrue(outcome.result.injected)
        assertEquals("Bearer resolved-value", outcome.headers["authorization"])
    }

    @Test
    fun `allowed secret ids are normalized for matching`() {
        val materializer = SecretMaterializer(object : SecretProvider {
            override fun resolve(secretId: String): SecretValue? = SecretValue("resolved-value")
        })

        val outcome = materializer.inject(
            headers = mapOf("authorization" to "OAG_PLACEHOLDER_OPENAI_KEY"),
            allowedSecretIds = setOf(" OPENAI_KEY ")
        )

        assertTrue(outcome.result.injected)
        assertEquals("resolved-value", outcome.headers["authorization"])
    }

    @Test
    fun `provider returning null prevents injection`() {
        val materializer = SecretMaterializer(object : SecretProvider {
            override fun resolve(secretId: String): SecretValue? = null
        })

        val outcome = materializer.inject(
            headers = mapOf("authorization" to "OAG_PLACEHOLDER_OPENAI_KEY"),
            allowedSecretIds = setOf("OPENAI_KEY")
        )

        assertFalse(outcome.result.injected)
        assertEquals("OAG_PLACEHOLDER_OPENAI_KEY", outcome.headers["authorization"])
        assertTrue(outcome.result.errors.any { it.contains("OPENAI_KEY") })
    }

    @Test
    fun `empty placeholder id is rejected`() {
        val materializer = SecretMaterializer(object : SecretProvider {
            override fun resolve(secretId: String): SecretValue? = SecretValue("resolved-value")
        })

        val outcome = materializer.inject(
            headers = mapOf("authorization" to "OAG_PLACEHOLDER_"),
            allowedSecretIds = setOf("OPENAI_KEY")
        )

        assertFalse(outcome.result.injected)
        assertTrue(outcome.result.errors.any { it == "secret_invalid_id:<empty>" })
    }
}
