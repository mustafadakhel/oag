package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.HeaderRewriteAction
import com.mustafadakhel.oag.policy.core.PatternAnchor
import com.mustafadakhel.oag.policy.core.PolicyAnchoredPattern
import com.mustafadakhel.oag.policy.core.PolicyCondition
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyHeaderRewrite
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.SecretScope

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PolicyCanonicalizerTest {
    @Test
    fun `canonicalizer sorts rule lists`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "b",
                    host = "api.example.com",
                    methods = listOf("POST", "GET"),
                    paths = listOf("/v1/models", "/v1/*"),
                    secrets = listOf("Z", "A")
                )
            )
        )

        val canonical = canonicalizePolicy(policy)
        val rule = requireNotNull(canonical.allow).first()

        assertEquals(listOf("GET", "POST"), rule.methods)
        assertEquals(listOf("/v1/*", "/v1/models"), rule.paths)
        assertEquals(listOf("A", "Z"), rule.secrets)
    }

    @Test
    fun `canonicalizer sorts ip ranges in rules`() {
        val policy = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(
                    id = "blocked",
                    host = "10.0.0.1",
                    ipRanges = listOf("fd00::/8", "10.0.0.0/24", "192.168.0.0/16")
                )
            )
        )

        val canonical = canonicalizePolicy(policy)
        val rule = requireNotNull(canonical.deny).first()

        assertEquals(listOf("10.0.0.0/24", "192.168.0.0/16", "fd00::/8"), rule.ipRanges)
    }

    @Test
    fun `canonicalizer sorts and includes secret scopes`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a", host = "api.example.com")),
            secretScopes = listOf(
                SecretScope(
                    id = "Z_KEY",
                    hosts = listOf("z.example.com", "a.example.com"),
                    methods = listOf("POST", "GET"),
                    paths = listOf("/v2/*", "/v1/*")
                ),
                SecretScope(
                    id = "A_KEY",
                    hosts = listOf("b.example.com")
                )
            )
        )

        val canonical = canonicalizePolicy(policy)
        val scopes = requireNotNull(canonical.secretScopes)

        assertEquals(2, scopes.size)
        assertEquals("A_KEY", scopes[0].id)
        assertEquals("Z_KEY", scopes[1].id)

        val zScope = scopes[1]
        assertEquals(listOf("a.example.com", "z.example.com"), zScope.hosts)
        assertEquals(listOf("GET", "POST"), zScope.methods)
        assertEquals(listOf("/v1/*", "/v2/*"), zScope.paths)
    }

    @Test
    fun `canonicalizer handles null secret scopes`() {
        val policy = PolicyDocument(version = 1, allow = listOf(PolicyRule(id = "a", host = "x.com")))
        val canonical = canonicalizePolicy(policy)
        assertNull(canonical.secretScopes)
    }

    @Test
    fun `canonicalizer handles null ip ranges in rules`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a", host = "x.com", ipRanges = null))
        )
        val canonical = canonicalizePolicy(policy)
        assertNull(requireNotNull(canonical.allow).first().ipRanges)
    }

    @Test
    fun `canonicalizer sorts condition ports`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "sorted_ports",
                    host = "api.example.com",
                    conditions = PolicyCondition(scheme = "https", ports = listOf(8443, 443, 80))
                )
            )
        )

        val canonical = canonicalizePolicy(policy)
        val cond = requireNotNull(requireNotNull(canonical.allow).first().conditions)

        assertEquals("https", cond.scheme)
        assertEquals(listOf(80, 443, 8443), cond.ports)
    }

    @Test
    fun `canonicalizer preserves null conditions`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a", host = "x.com", conditions = null))
        )
        val canonical = canonicalizePolicy(policy)
        assertNull(requireNotNull(canonical.allow).first().conditions)
    }

    @Test
    fun `canonicalizer sorts secret scope ip ranges`() {
        val policy = PolicyDocument(
            version = 1,
            secretScopes = listOf(
                SecretScope(
                    id = "KEY",
                    hosts = listOf("api.example.com"),
                    ipRanges = listOf("192.168.0.0/16", "10.0.0.0/8")
                )
            )
        )
        val canonical = canonicalizePolicy(policy)
        val scope = requireNotNull(canonical.secretScopes).first()
        assertEquals(listOf("10.0.0.0/8", "192.168.0.0/16"), scope.ipRanges)
    }

    @Test
    fun `canonicalizer sorts anchored patterns by pattern then anchor`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    contentInspection = PolicyContentInspection(
                        anchoredPatterns = listOf(
                            PolicyAnchoredPattern("zzz_pattern", PatternAnchor.ANY),
                            PolicyAnchoredPattern("aaa_pattern", PatternAnchor.STANDALONE),
                            PolicyAnchoredPattern("aaa_pattern", PatternAnchor.ANY)
                        )
                    )
                )
            )
        )
        val canonical = canonicalizePolicy(policy)
        val anchored = requireNotNull(requireNotNull(canonical.allow).first().contentInspection?.anchoredPatterns)
        assertEquals(3, anchored.size)
        assertEquals("aaa_pattern", anchored[0].pattern)
        assertEquals(PatternAnchor.ANY, anchored[0].anchor)
        assertEquals("aaa_pattern", anchored[1].pattern)
        assertEquals(PatternAnchor.STANDALONE, anchored[1].anchor)
        assertEquals("zzz_pattern", anchored[2].pattern)
    }

    @Test
    fun `canonicalize sorts header rewrites by header then action`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerRewrites = listOf(
                        PolicyHeaderRewrite(action = HeaderRewriteAction.REMOVE, header = "X-Zebra"),
                        PolicyHeaderRewrite(action = HeaderRewriteAction.SET, header = "X-Alpha", value = "val1"),
                        PolicyHeaderRewrite(action = HeaderRewriteAction.APPEND, header = "X-Alpha", value = "val2")
                    )
                )
            )
        )
        val canonical = canonicalizePolicy(policy)
        val rewrites = requireNotNull(requireNotNull(canonical.allow).first().headerRewrites)
        assertEquals(3, rewrites.size)
        assertEquals("X-Alpha", rewrites[0].header)
        assertEquals(HeaderRewriteAction.APPEND, rewrites[0].action)
        assertEquals("X-Alpha", rewrites[1].header)
        assertEquals(HeaderRewriteAction.SET, rewrites[1].action)
        assertEquals("X-Zebra", rewrites[2].header)
        assertEquals(HeaderRewriteAction.REMOVE, rewrites[2].action)
    }

    @Test
    fun `canonicalize preserves null header rewrites`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com")
            )
        )
        val canonical = canonicalizePolicy(policy)
        assertEquals(null, requireNotNull(canonical.allow).first().headerRewrites)
    }

    @Test
    fun `canonicalize sorts tags alphabetically`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com", tags = listOf("zebra", "alpha", "mid"))
            )
        )
        val canonical = canonicalizePolicy(policy)
        val tags = requireNotNull(canonical.allow).first().tags
        assertEquals(listOf("alpha", "mid", "zebra"), tags)
    }

    @Test
    fun `canonicalize sorts webhookEvents alphabetically`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    webhookEvents = listOf("reload_failed", "circuit_open", "injection_detected")
                )
            )
        )
        val canonical = canonicalizePolicy(policy)
        val events = requireNotNull(requireNotNull(canonical.allow).first().webhookEvents)
        assertEquals(listOf("circuit_open", "injection_detected", "reload_failed"), events)
    }
}
