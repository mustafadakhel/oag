package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyCondition
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.SecretScope

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PolicyLinterTest {


    @Test
    fun `lint returns empty list for minimal valid policy`() {
        val doc = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY)
        )
        val warnings = lintPolicy(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `lint returns empty list for policy with non-overlapping rules`() {
        val doc = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY),
            allow = listOf(
                PolicyRule(id = "r1", host = "api.openai.com", methods = listOf("POST"), paths = listOf("/v1/*")),
                PolicyRule(id = "r2", host = "api.github.com", methods = listOf("GET"), paths = listOf("/repos/*"))
            )
        )
        val warnings = lintPolicy(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `LintWarning stores code and message`() {
        val warning = LintWarning(
            code = LintCode.SHADOWED_RULE,
            message = "test message",
            ruleId = "r1",
            ruleIndex = 0,
            section = "allow"
        )
        assertEquals(LintCode.SHADOWED_RULE, warning.code)
        assertEquals("test message", warning.message)
        assertEquals("r1", warning.ruleId)
        assertEquals(0, warning.ruleIndex)
        assertEquals("allow", warning.section)
    }

    @Test
    fun `lint returns empty list for null allow and deny`() {
        val doc = PolicyDocument(version = 1)
        val warnings = lintPolicy(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `shadowed rule detected when identical rules in allow`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com"),
                PolicyRule(id = "r2", host = "api.example.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertEquals(1, warnings.size)
        assertEquals(LintCode.SHADOWED_RULE, warnings[0].code)
        assertEquals("r2", warnings[0].ruleId)
        assertEquals(1, warnings[0].ruleIndex)
        assertEquals("allow", warnings[0].section)
    }

    @Test
    fun `shadowed rule detected in deny section`() {
        val doc = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(id = "d1", host = "evil.com"),
                PolicyRule(id = "d2", host = "evil.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertEquals(1, warnings.size)
        assertEquals("deny", warnings[0].section)
        assertEquals("d2", warnings[0].ruleId)
    }

    @Test
    fun `wildcard host shadows specific host`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "*.example.com"),
                PolicyRule(id = "r2", host = "api.example.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertEquals(1, warnings.size)
        assertEquals("r2", warnings[0].ruleId)
    }

    @Test
    fun `specific host does not shadow wildcard host`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com"),
                PolicyRule(id = "r2", host = "*.example.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `broader method list shadows narrower`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com", methods = listOf("GET", "POST")),
                PolicyRule(id = "r2", host = "api.example.com", methods = listOf("GET"))
            )
        )
        val warnings = checkShadowedRules(doc)
        assertEquals(1, warnings.size)
        assertEquals("r2", warnings[0].ruleId)
    }

    @Test
    fun `null methods shadow specific methods`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com"),
                PolicyRule(id = "r2", host = "api.example.com", methods = listOf("GET"))
            )
        )
        val warnings = checkShadowedRules(doc)
        assertEquals(1, warnings.size)
    }

    @Test
    fun `broader path shadows narrower path`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com", paths = listOf("/v1/*")),
                PolicyRule(id = "r2", host = "api.example.com", paths = listOf("/v1/chat"))
            )
        )
        val warnings = checkShadowedRules(doc)
        assertEquals(1, warnings.size)
        assertEquals("r2", warnings[0].ruleId)
    }

    @Test
    fun `rule with ip_ranges does not shadow`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com", ipRanges = listOf("10.0.0.0/8")),
                PolicyRule(id = "r2", host = "api.example.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `rule with conditions does not shadow`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com", conditions = PolicyCondition(scheme = "https")),
                PolicyRule(id = "r2", host = "api.example.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `rule with body_match does not shadow`() {
        val doc = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(id = "d1", host = "api.example.com", bodyMatch = PolicyBodyMatch(contains = listOf("secret"))),
                PolicyRule(id = "d2", host = "api.example.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `no shadow when rules use different hosts`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.openai.com"),
                PolicyRule(id = "r2", host = "api.github.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `only first shadowing rule reported`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com"),
                PolicyRule(id = "r2", host = "api.example.com"),
                PolicyRule(id = "r3", host = "api.example.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertEquals(2, warnings.size)
        assertEquals("r2", warnings[0].ruleId)
        assertEquals("r3", warnings[1].ruleId)
    }

    @Test
    fun `rules without ids use index in message`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(host = "api.example.com"),
                PolicyRule(host = "api.example.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertEquals(1, warnings.size)
        assertTrue(warnings[0].message.contains("index 1"))
        assertTrue(warnings[0].message.contains("index 0"))
    }

    @Test
    fun `hostCovers exact match`() {
        assertTrue(hostCovers("api.example.com", "api.example.com"))
    }

    @Test
    fun `hostCovers wildcard covers subdomain`() {
        assertTrue(hostCovers("*.example.com", "api.example.com"))
    }

    @Test
    fun `hostCovers wildcard covers nested subdomain wildcard`() {
        assertTrue(hostCovers("*.example.com", "*.sub.example.com"))
    }

    @Test
    fun `hostCovers wildcard does not cover parent`() {
        assertFalse(hostCovers("*.sub.example.com", "api.example.com"))
    }

    @Test
    fun `hostCovers null host returns false`() {
        assertFalse(hostCovers(null, "api.example.com"))
        assertFalse(hostCovers("api.example.com", null))
    }

    @Test
    fun `methodsCovers null covers anything`() {
        assertTrue(methodsCovers(null, listOf("GET")))
        assertTrue(methodsCovers(null, null))
    }

    @Test
    fun `methodsCovers specific cannot cover all`() {
        assertFalse(methodsCovers(listOf("GET"), null))
    }

    @Test
    fun `methodsCovers superset covers subset`() {
        assertTrue(methodsCovers(listOf("GET", "POST"), listOf("GET")))
    }

    @Test
    fun `methodsCovers subset cannot cover superset`() {
        assertFalse(methodsCovers(listOf("GET"), listOf("GET", "POST")))
    }

    @Test
    fun `pathsCovers null covers anything`() {
        assertTrue(pathsCovers(null, listOf("/v1/*")))
    }

    @Test
    fun `pathsCovers specific cannot cover all`() {
        assertFalse(pathsCovers(listOf("/v1/*"), null))
    }

    @Test
    fun `pathsCovers wildcard covers specific`() {
        assertTrue(pathsCovers(listOf("/v1/*"), listOf("/v1/chat")))
    }

    @Test
    fun `pathsCovers star covers everything`() {
        assertTrue(pathsCovers(listOf("*"), listOf("/anything/at/all")))
    }

    @Test
    fun `globCovers star covers anything`() {
        assertTrue(globCovers("*", "/foo/bar"))
    }

    @Test
    fun `globCovers exact match`() {
        assertTrue(globCovers("/v1/chat", "/v1/chat"))
    }

    @Test
    fun `globCovers prefix wildcard`() {
        assertTrue(globCovers("/v1/*", "/v1/chat"))
        assertTrue(globCovers("/v1/*", "/v1/chat/completions"))
    }

    @Test
    fun `globCovers different prefix no cover`() {
        assertFalse(globCovers("/v1/*", "/v2/chat"))
    }

    @Test
    fun `overlap detected between allow and deny with same host`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a1", host = "api.example.com")),
            deny = listOf(PolicyRule(id = "d1", host = "api.example.com"))
        )
        val warnings = checkOverlappingRules(doc)
        assertEquals(1, warnings.size)
        assertEquals(LintCode.OVERLAPPING_RULES, warnings[0].code)
        assertTrue(warnings[0].message.contains("a1"))
        assertTrue(warnings[0].message.contains("d1"))
    }

    @Test
    fun `no overlap when hosts differ`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a1", host = "api.openai.com")),
            deny = listOf(PolicyRule(id = "d1", host = "evil.com"))
        )
        val warnings = checkOverlappingRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `overlap between wildcard allow and specific deny`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a1", host = "*.example.com")),
            deny = listOf(PolicyRule(id = "d1", host = "api.example.com"))
        )
        val warnings = checkOverlappingRules(doc)
        assertEquals(1, warnings.size)
    }

    @Test
    fun `no overlap when methods are disjoint`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a1", host = "api.example.com", methods = listOf("GET"))),
            deny = listOf(PolicyRule(id = "d1", host = "api.example.com", methods = listOf("DELETE")))
        )
        val warnings = checkOverlappingRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `overlap when methods share common element`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a1", host = "api.example.com", methods = listOf("GET", "POST"))),
            deny = listOf(PolicyRule(id = "d1", host = "api.example.com", methods = listOf("POST", "DELETE")))
        )
        val warnings = checkOverlappingRules(doc)
        assertEquals(1, warnings.size)
    }

    @Test
    fun `no overlap when paths are disjoint`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a1", host = "api.example.com", paths = listOf("/v1/*"))),
            deny = listOf(PolicyRule(id = "d1", host = "api.example.com", paths = listOf("/v2/*")))
        )
        val warnings = checkOverlappingRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `overlap when paths share prefix`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a1", host = "api.example.com", paths = listOf("/v1/*"))),
            deny = listOf(PolicyRule(id = "d1", host = "api.example.com", paths = listOf("/v1/chat")))
        )
        val warnings = checkOverlappingRules(doc)
        assertEquals(1, warnings.size)
    }

    @Test
    fun `no overlap with empty allow or deny`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a1", host = "api.example.com")),
            deny = null
        )
        val warnings = checkOverlappingRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `hostsOverlap exact match`() {
        assertTrue(hostsOverlap("api.example.com", "api.example.com"))
    }

    @Test
    fun `hostsOverlap wildcard and subdomain`() {
        assertTrue(hostsOverlap("*.example.com", "api.example.com"))
        assertTrue(hostsOverlap("api.example.com", "*.example.com"))
    }

    @Test
    fun `hostsOverlap different domains`() {
        assertFalse(hostsOverlap("api.openai.com", "api.github.com"))
    }

    @Test
    fun `hostsOverlap null returns false`() {
        assertFalse(hostsOverlap(null, "api.example.com"))
    }

    @Test
    fun `methodsOverlap null means all`() {
        assertTrue(methodsOverlap(null, listOf("GET")))
        assertTrue(methodsOverlap(listOf("GET"), null))
    }

    @Test
    fun `methodsOverlap shared element`() {
        assertTrue(methodsOverlap(listOf("GET", "POST"), listOf("POST", "DELETE")))
    }

    @Test
    fun `methodsOverlap disjoint`() {
        assertFalse(methodsOverlap(listOf("GET"), listOf("POST")))
    }

    @Test
    fun `globsOverlap star overlaps anything`() {
        assertTrue(globsOverlap("*", "/foo"))
        assertTrue(globsOverlap("/foo", "*"))
    }

    @Test
    fun `globsOverlap exact match`() {
        assertTrue(globsOverlap("/v1/chat", "/v1/chat"))
    }

    @Test
    fun `globsOverlap wildcard and literal`() {
        assertTrue(globsOverlap("/v1/*", "/v1/chat"))
        assertTrue(globsOverlap("/v1/chat", "/v1/*"))
    }

    @Test
    fun `globsOverlap nested wildcards`() {
        assertTrue(globsOverlap("/v1/*", "/v1/chat/*"))
    }

    @Test
    fun `globsOverlap disjoint`() {
        assertFalse(globsOverlap("/v1/*", "/v2/*"))
    }

    @Test
    fun `globsOverlap disjoint literals`() {
        assertFalse(globsOverlap("/v1/chat", "/v2/chat"))
    }

    @Test
    fun `unused secret detected when rule references undefined secret`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com", secrets = listOf("openai-key"))
            ),
            secretScopes = emptyList()
        )
        val warnings = checkUnusedSecrets(doc)
        assertEquals(1, warnings.size)
        assertEquals(LintCode.UNUSED_SECRET_REF, warnings[0].code)
        assertTrue(warnings[0].message.contains("openai-key"))
        assertEquals("r1", warnings[0].ruleId)
        assertEquals("allow", warnings[0].section)
    }

    @Test
    fun `no warning when secret is defined in secret_scopes`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com", secrets = listOf("openai-key"))
            ),
            secretScopes = listOf(SecretScope(id = "openai-key"))
        )
        val warnings = checkUnusedSecrets(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `unused secret in deny section detected`() {
        val doc = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(id = "d1", host = "evil.com", secrets = listOf("bad-secret"))
            ),
            secretScopes = listOf(SecretScope(id = "other-secret"))
        )
        val warnings = checkUnusedSecrets(doc)
        assertEquals(1, warnings.size)
        assertEquals("deny", warnings[0].section)
    }

    @Test
    fun `multiple unused secrets from single rule`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com", secrets = listOf("key-a", "key-b"))
            ),
            secretScopes = listOf(SecretScope(id = "key-a"))
        )
        val warnings = checkUnusedSecrets(doc)
        assertEquals(1, warnings.size)
        assertTrue(warnings[0].message.contains("key-b"))
    }

    @Test
    fun `no warning when rules have no secrets`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com")
            )
        )
        val warnings = checkUnusedSecrets(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `no warning when secret_scopes is null and no secrets referenced`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "r1", host = "api.example.com"))
        )
        val warnings = checkUnusedSecrets(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `lint reports all warning types together`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "a1", host = "api.example.com"),
                PolicyRule(id = "a2", host = "api.example.com", secrets = listOf("missing-secret"))
            ),
            deny = listOf(
                PolicyRule(id = "d1", host = "api.example.com")
            ),
            secretScopes = emptyList()
        )
        val warnings = lintPolicy(doc)
        val codes = warnings.map { it.code }.toSet()
        assertTrue(LintCode.SHADOWED_RULE in codes, "expected SHADOWED_RULE warning")
        assertTrue(LintCode.OVERLAPPING_RULES in codes, "expected OVERLAPPING_RULES warning")
        assertTrue(LintCode.UNUSED_SECRET_REF in codes, "expected UNUSED_SECRET_REF warning")
    }

    @Test
    fun `shadowed rules in allow do not affect deny section`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "a1", host = "api.example.com"),
                PolicyRule(id = "a2", host = "api.example.com")
            ),
            deny = listOf(
                PolicyRule(id = "d1", host = "evil.com")
            )
        )
        val warnings = checkShadowedRules(doc)
        assertEquals(1, warnings.size)
        assertEquals("allow", warnings[0].section)
    }

    @Test
    fun `shadowed rule with narrower methods not flagged`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "r1", host = "api.example.com", methods = listOf("GET")),
                PolicyRule(id = "r2", host = "api.example.com", methods = listOf("GET", "POST"))
            )
        )
        val warnings = checkShadowedRules(doc)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun `overlap message contains deny takes precedence`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "a1", host = "api.example.com")),
            deny = listOf(PolicyRule(id = "d1", host = "api.example.com"))
        )
        val warnings = checkOverlappingRules(doc)
        assertTrue(warnings[0].message.contains("deny takes precedence"))
    }

    @Test
    fun `unused secret ref warning includes rule index for rule without id`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(host = "api.example.com", secrets = listOf("missing"))
            ),
            secretScopes = emptyList()
        )
        val warnings = checkUnusedSecrets(doc)
        assertEquals(1, warnings.size)
        assertTrue(warnings[0].message.contains("index 0"))
        assertEquals(null, warnings[0].ruleId)
    }

    @Test
    fun `multiple allow-deny overlaps detected`() {
        val doc = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "a1", host = "api.example.com"),
                PolicyRule(id = "a2", host = "api.github.com")
            ),
            deny = listOf(
                PolicyRule(id = "d1", host = "api.example.com"),
                PolicyRule(id = "d2", host = "api.github.com")
            )
        )
        val warnings = checkOverlappingRules(doc)
        assertEquals(2, warnings.size)
    }

    @Test
    fun `hostCovers case insensitive`() {
        assertTrue(hostCovers("API.Example.COM", "api.example.com"))
        assertTrue(hostCovers("*.EXAMPLE.COM", "api.example.com"))
    }

    @Test
    fun `methodsCovers case insensitive`() {
        assertTrue(methodsCovers(listOf("get"), listOf("GET")))
    }

    @Test
    fun `pathsOverlap null paths overlap with anything`() {
        assertTrue(pathsOverlap(null, listOf("/v1/*")))
        assertTrue(pathsOverlap(listOf("/v1/*"), null))
        assertTrue(pathsOverlap(null, null))
    }

    @Test
    fun `unreachable allow rule detected when deny covers all traffic`() {
        val policy = PolicyDocument(
            version = 1,
            deny = listOf(PolicyRule(id = "deny-all", host = "*.example.com")),
            allow = listOf(PolicyRule(id = "allow-api", host = "api.example.com", methods = listOf("GET")))
        )
        val warnings = checkUnreachableAllowRules(policy)
        assertTrue(warnings.any { it.code == LintCode.UNREACHABLE_ALLOW && it.ruleId == "allow-api" })
    }

    @Test
    fun `no unreachable allow when deny does not cover`() {
        val policy = PolicyDocument(
            version = 1,
            deny = listOf(PolicyRule(id = "deny-other", host = "other.example.com")),
            allow = listOf(PolicyRule(id = "allow-api", host = "api.example.com"))
        )
        val warnings = checkUnreachableAllowRules(policy)
        assertTrue(warnings.none { it.code == LintCode.UNREACHABLE_ALLOW })
    }

    @Test
    fun `unsafe regex detected in body match pattern`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rule-bad-regex",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch(patterns = listOf("a".repeat(1025)))
                )
            )
        )
        val warnings = checkUnsafeRegex(policy)
        assertTrue(warnings.any { it.code == LintCode.UNSAFE_REGEX && it.ruleId == "rule-bad-regex" })
    }

    @Test
    fun `safe regex produces no warning`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rule-safe",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch(patterns = listOf("simple-pattern"))
                )
            )
        )
        val warnings = checkUnsafeRegex(policy)
        assertTrue(warnings.none { it.code == LintCode.UNSAFE_REGEX })
    }
}
