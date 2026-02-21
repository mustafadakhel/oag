package com.mustafadakhel.oag.policy.distribution

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.SecretScope

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PolicyDiffTest {
    @Test
    fun `identical policies produce no changes`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY),
            allow = listOf(PolicyRule(id = "api", host = "api.example.com", methods = listOf("GET"))),
            deny = emptyList()
        )
        val result = diffPolicies(policy, policy)
        assertFalse(result.hasChanges)
        assertFalse(result.defaultsChanged)
        assertTrue(result.ruleDiffs.isEmpty())
        assertTrue(result.secretScopeDiffs.isEmpty())
    }

    @Test
    fun `added allow rule detected`() {
        val old = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY),
            allow = emptyList()
        )
        val new = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY),
            allow = listOf(PolicyRule(id = "api", host = "api.example.com"))
        )
        val result = diffPolicies(old, new)
        assertTrue(result.hasChanges)
        assertEquals(1, result.ruleDiffs.size)
        assertEquals(DiffChangeType.ADDED, result.ruleDiffs[0].change)
        assertEquals("api", result.ruleDiffs[0].id)
        assertEquals("allow", result.ruleDiffs[0].section)
    }

    @Test
    fun `removed allow rule detected`() {
        val old = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY),
            allow = listOf(PolicyRule(id = "api", host = "api.example.com"))
        )
        val new = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY),
            allow = emptyList()
        )
        val result = diffPolicies(old, new)
        assertTrue(result.hasChanges)
        assertEquals(1, result.ruleDiffs.size)
        assertEquals(DiffChangeType.REMOVED, result.ruleDiffs[0].change)
        assertEquals("api", result.ruleDiffs[0].id)
    }

    @Test
    fun `changed rule fields detected with details`() {
        val old = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "api", host = "api.old.com", methods = listOf("GET")))
        )
        val new = PolicyDocument(
            version = 1,
            allow = listOf(PolicyRule(id = "api", host = "api.new.com", methods = listOf("GET", "POST")))
        )
        val result = diffPolicies(old, new)
        assertTrue(result.hasChanges)
        assertEquals(1, result.ruleDiffs.size)
        assertEquals(DiffChangeType.CHANGED, result.ruleDiffs[0].change)
        assertTrue(result.ruleDiffs[0].details.any { it.contains("host:") })
        assertTrue(result.ruleDiffs[0].details.any { it.contains("methods:") })
    }

    @Test
    fun `defaults change detected`() {
        val old = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY, maxBodyBytes = 1024)
        )
        val new = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY, maxBodyBytes = 2048)
        )
        val result = diffPolicies(old, new)
        assertTrue(result.hasChanges)
        assertTrue(result.defaultsChanged)
        assertTrue(result.defaultsDetails.any { it.contains("max_body_bytes") })
    }

    @Test
    fun `deny rule changes detected`() {
        val old = PolicyDocument(
            version = 1,
            deny = listOf(PolicyRule(id = "block_meta", host = "169.254.169.254"))
        )
        val new = PolicyDocument(
            version = 1,
            deny = emptyList()
        )
        val result = diffPolicies(old, new)
        assertTrue(result.hasChanges)
        assertEquals(1, result.ruleDiffs.size)
        assertEquals("deny", result.ruleDiffs[0].section)
        assertEquals(DiffChangeType.REMOVED, result.ruleDiffs[0].change)
    }

    @Test
    fun `secret scope added detected`() {
        val old = PolicyDocument(version = 1, secretScopes = emptyList())
        val new = PolicyDocument(
            version = 1,
            secretScopes = listOf(SecretScope(id = "API_KEY", hosts = listOf("api.example.com")))
        )
        val result = diffPolicies(old, new)
        assertTrue(result.hasChanges)
        assertEquals(1, result.secretScopeDiffs.size)
        assertEquals(DiffChangeType.ADDED, result.secretScopeDiffs[0].change)
        assertEquals("API_KEY", result.secretScopeDiffs[0].id)
    }

    @Test
    fun `secret scope changed detected`() {
        val old = PolicyDocument(
            version = 1,
            secretScopes = listOf(SecretScope(id = "API_KEY", hosts = listOf("api.old.com")))
        )
        val new = PolicyDocument(
            version = 1,
            secretScopes = listOf(SecretScope(id = "API_KEY", hosts = listOf("api.new.com")))
        )
        val result = diffPolicies(old, new)
        assertTrue(result.hasChanges)
        assertEquals(1, result.secretScopeDiffs.size)
        assertEquals(DiffChangeType.CHANGED, result.secretScopeDiffs[0].change)
        assertTrue(result.secretScopeDiffs[0].details.any { it.contains("hosts:") })
    }

    @Test
    fun `multiple changes across sections`() {
        val old = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.DENY),
            allow = listOf(
                PolicyRule(id = "api1", host = "api.example.com"),
                PolicyRule(id = "api2", host = "api.other.com")
            ),
            deny = listOf(PolicyRule(id = "block", host = "evil.com"))
        )
        val new = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.ALLOW),
            allow = listOf(
                PolicyRule(id = "api1", host = "api.example.com"),
                PolicyRule(id = "api3", host = "api.new.com")
            ),
            deny = listOf(PolicyRule(id = "block", host = "evil.com"))
        )
        val result = diffPolicies(old, new)
        assertTrue(result.hasChanges)
        assertTrue(result.defaultsChanged)
        val removed = result.ruleDiffs.filter { it.change == DiffChangeType.REMOVED }
        val added = result.ruleDiffs.filter { it.change == DiffChangeType.ADDED }
        assertEquals(1, removed.size)
        assertEquals("api2", removed[0].id)
        assertEquals(1, added.size)
        assertEquals("api3", added[0].id)
    }

    @Test
    fun `diffDefaults covers all PolicyDefaults fields`() {
        // Count constructor parameters (= serializable properties) via component functions.
        val componentCount = PolicyDefaults::class.java.declaredMethods
            .count { it.name.startsWith("component") }
        // diffDefaults manually enumerates all PolicyDefaults fields.
        // If a new field is added to PolicyDefaults without updating diffDefaults,
        // this assertion will fail, reminding you to add it.
        val coveredCount = 18
        assertEquals(
            coveredCount, componentCount,
            "PolicyDefaults has $componentCount data class components but diffDefaults covers $coveredCount. " +
                "Add the new field(s) to diffDefaults in PolicyDiff.kt"
        )
    }

    @Test
    fun `diffRule covers all PolicyRule fields`() {
        val componentCount = PolicyRule::class.java.declaredMethods
            .count { it.name.startsWith("component") }
        // diffRule manually enumerates PolicyRule fields (excludes `id` which is used for matching, not diffing).
        // Update diffRule in PolicyDiff.kt when adding new PolicyRule fields.
        val coveredCount = componentCount - 1
        val actualDiffEntries = 32
        assertEquals(
            coveredCount, actualDiffEntries,
            "PolicyRule has $componentCount components (minus id = $coveredCount) but diffRule covers $actualDiffEntries. " +
                "Add the new field(s) to diffRule in PolicyDiff.kt"
        )
    }
}
