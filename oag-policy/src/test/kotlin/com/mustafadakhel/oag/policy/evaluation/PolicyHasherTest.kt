package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.SecretScope

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class PolicyHasherTest {
    @Test
    fun `policy hash stable across ordering and casing`() {
        val policyA = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "b",
                    host = "API.EXAMPLE.COM",
                    methods = listOf("post", "GET"),
                    paths = listOf("/v1/*", "/v1/models")
                ),
                PolicyRule(
                    id = "a",
                    host = "api.example.com",
                    methods = listOf("GET"),
                    paths = listOf("/v1/*")
                )
            )
        )

        val policyB = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "a",
                    host = "api.example.com",
                    methods = listOf("GET"),
                    paths = listOf("/v1/*")
                ),
                PolicyRule(
                    id = "b",
                    host = "api.example.com",
                    methods = listOf("GET", "POST"),
                    paths = listOf("/v1/models", "/v1/*")
                )
            )
        )

        val hashA = hashPolicy(policyA)
        val hashB = hashPolicy(policyB)

        assertEquals(hashA, hashB)
    }

    @Test
    fun `policy hash stable across ip range ordering`() {
        val policyA = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(
                    id = "blocked",
                    host = "*.internal.com",
                    ipRanges = listOf("10.0.0.0/8", "192.168.0.0/16")
                )
            )
        )
        val policyB = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(
                    id = "blocked",
                    host = "*.internal.com",
                    ipRanges = listOf("192.168.0.0/16", "10.0.0.0/8")
                )
            )
        )

        assertEquals(hashPolicy(policyA), hashPolicy(policyB))
    }

    @Test
    fun `policy hash stable across secret scope ordering`() {
        val policyA = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a", host = "api.example.com", secrets = listOf("K1"))),
            secretScopes = listOf(
                SecretScope(id = "K2", hosts = listOf("b.example.com")),
                SecretScope(id = "K1", hosts = listOf("a.example.com"))
            )
        )
        val policyB = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a", host = "api.example.com", secrets = listOf("K1"))),
            secretScopes = listOf(
                SecretScope(id = "K1", hosts = listOf("a.example.com")),
                SecretScope(id = "K2", hosts = listOf("b.example.com"))
            )
        )

        assertEquals(hashPolicy(policyA), hashPolicy(policyB))
    }

    @Test
    fun `policy hash differs when secret scopes differ`() {
        val policyA = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a", host = "api.example.com", secrets = listOf("K1")))
        )
        val policyB = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a", host = "api.example.com", secrets = listOf("K1"))),
            secretScopes = listOf(SecretScope(id = "K1", hosts = listOf("api.example.com")))
        )

        assertNotEquals(hashPolicy(policyA), hashPolicy(policyB))
    }

    @Test
    fun `policy hash stable across secret scope field ordering`() {
        val policyA = PolicyDocument(
            version = 1,
            secretScopes = listOf(
                SecretScope(id = "K1", hosts = listOf("b.example.com", "a.example.com"), methods = listOf("POST", "GET"))
            )
        )
        val policyB = PolicyDocument(
            version = 1,
            secretScopes = listOf(
                SecretScope(id = "K1", hosts = listOf("a.example.com", "b.example.com"), methods = listOf("GET", "POST"))
            )
        )

        assertEquals(hashPolicy(policyA), hashPolicy(policyB))
    }
}
