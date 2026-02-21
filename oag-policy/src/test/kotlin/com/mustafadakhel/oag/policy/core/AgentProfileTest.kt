package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.policy.evaluation.evaluatePolicyWithRule

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class AgentProfileTest {

    @Test
    fun `no agent profile evaluates all rules normally`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule-a", host = "*.example.com"),
                PolicyRule(id = "rule-b", host = "*.other.com")
            ),
            deny = listOf(
                PolicyRule(id = "deny-all", host = "*.blocked.com")
            )
        )

        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val result = evaluatePolicyWithRule(policy, request)

        assertEquals(PolicyAction.ALLOW, result.decision.action)
        assertEquals("rule-a", result.decision.ruleId)
        assertEquals(ReasonCode.ALLOWED_BY_RULE, result.decision.reasonCode)
    }

    @Test
    fun `null agent profile does not filter rules`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule-a", host = "*.example.com"),
                PolicyRule(id = "rule-b", host = "*.other.com")
            )
        )

        val request = PolicyRequest("https", "sub.other.com", 443, "GET", "/")
        val result = evaluatePolicyWithRule(policy, request, agentProfile = null)

        assertEquals(PolicyAction.ALLOW, result.decision.action)
        assertEquals("rule-b", result.decision.ruleId)
    }

    @Test
    fun `agent profile with allowedRules only evaluates specified rules`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule-a", host = "*.example.com"),
                PolicyRule(id = "rule-b", host = "*.other.com")
            )
        )

        val profile = PolicyAgentProfile(id = "agent-1", allowedRules = listOf("rule-a"))

        val requestA = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val resultA = evaluatePolicyWithRule(policy, requestA, profile)
        assertEquals(PolicyAction.ALLOW, resultA.decision.action)
        assertEquals("rule-a", resultA.decision.ruleId)

        val requestB = PolicyRequest("https", "sub.other.com", 443, "GET", "/")
        val resultB = evaluatePolicyWithRule(policy, requestB, profile)
        assertEquals(PolicyAction.DENY, resultB.decision.action)
        assertEquals(ReasonCode.NO_MATCH_DEFAULT_DENY, resultB.decision.reasonCode)
        assertNull(resultB.decision.ruleId)
    }

    @Test
    fun `agent profile with deniedRules excludes specified rules`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule-a", host = "*.example.com"),
                PolicyRule(id = "rule-b", host = "*.other.com")
            )
        )

        val profile = PolicyAgentProfile(id = "agent-2", deniedRules = listOf("rule-a"))

        val requestA = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val resultA = evaluatePolicyWithRule(policy, requestA, profile)
        assertEquals(PolicyAction.DENY, resultA.decision.action)
        assertEquals(ReasonCode.NO_MATCH_DEFAULT_DENY, resultA.decision.reasonCode)
        assertNull(resultA.decision.ruleId)

        val requestB = PolicyRequest("https", "sub.other.com", 443, "GET", "/")
        val resultB = evaluatePolicyWithRule(policy, requestB, profile)
        assertEquals(PolicyAction.ALLOW, resultB.decision.action)
        assertEquals("rule-b", resultB.decision.ruleId)
    }

    @Test
    fun `allowedRules on allow rules causes fall-through to default deny when matching rule not in list`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule-a", host = "*.example.com"),
                PolicyRule(id = "rule-b", host = "*.other.com"),
                PolicyRule(id = "rule-c", host = "*.third.com")
            )
        )

        val profile = PolicyAgentProfile(id = "agent-3", allowedRules = listOf("rule-c"))

        val requestA = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val resultA = evaluatePolicyWithRule(policy, requestA, profile)
        assertEquals(PolicyAction.DENY, resultA.decision.action)
        assertEquals(ReasonCode.NO_MATCH_DEFAULT_DENY, resultA.decision.reasonCode)

        val requestB = PolicyRequest("https", "sub.other.com", 443, "GET", "/")
        val resultB = evaluatePolicyWithRule(policy, requestB, profile)
        assertEquals(PolicyAction.DENY, resultB.decision.action)
        assertEquals(ReasonCode.NO_MATCH_DEFAULT_DENY, resultB.decision.reasonCode)

        val requestC = PolicyRequest("https", "sub.third.com", 443, "GET", "/")
        val resultC = evaluatePolicyWithRule(policy, requestC, profile)
        assertEquals(PolicyAction.ALLOW, resultC.decision.action)
        assertEquals("rule-c", resultC.decision.ruleId)
    }

    @Test
    fun `allowedRules also filters deny rules`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "allow-all", host = "*.example.com")
            ),
            deny = listOf(
                PolicyRule(id = "deny-api", host = "api.example.com"),
                PolicyRule(id = "deny-internal", host = "internal.example.com")
            )
        )

        val profile = PolicyAgentProfile(id = "agent-4", allowedRules = listOf("allow-all", "deny-internal"))

        val requestApi = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val resultApi = evaluatePolicyWithRule(policy, requestApi, profile)
        assertEquals(PolicyAction.ALLOW, resultApi.decision.action)
        assertEquals("allow-all", resultApi.decision.ruleId)

        val requestInternal = PolicyRequest("https", "internal.example.com", 443, "GET", "/")
        val resultInternal = evaluatePolicyWithRule(policy, requestInternal, profile)
        assertEquals(PolicyAction.DENY, resultInternal.decision.action)
        assertEquals("deny-internal", resultInternal.decision.ruleId)
    }

    @Test
    fun `deniedRules also filters deny rules`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "allow-all", host = "*.example.com")
            ),
            deny = listOf(
                PolicyRule(id = "deny-api", host = "api.example.com")
            )
        )

        val profile = PolicyAgentProfile(id = "agent-5", deniedRules = listOf("deny-api"))

        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val result = evaluatePolicyWithRule(policy, request, profile)
        assertEquals(PolicyAction.ALLOW, result.decision.action)
        assertEquals("allow-all", result.decision.ruleId)
    }

    @Test
    fun `agent profile with empty allowedRules filters out all rules`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule-a", host = "*.example.com")
            )
        )

        val profile = PolicyAgentProfile(id = "agent-6", allowedRules = emptyList())

        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val result = evaluatePolicyWithRule(policy, request, profile)
        assertEquals(PolicyAction.DENY, result.decision.action)
        assertEquals(ReasonCode.NO_MATCH_DEFAULT_DENY, result.decision.reasonCode)
    }

    @Test
    fun `agent profile with default allow falls through to default allow when no rules match`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.ALLOW),
            allow = listOf(
                PolicyRule(id = "rule-a", host = "*.example.com")
            )
        )

        val profile = PolicyAgentProfile(id = "agent-7", allowedRules = listOf("rule-a"))

        val request = PolicyRequest("https", "api.unrelated.com", 443, "GET", "/")
        val result = evaluatePolicyWithRule(policy, request, profile)
        assertEquals(PolicyAction.ALLOW, result.decision.action)
        assertEquals(ReasonCode.NO_MATCH_DEFAULT_ALLOW, result.decision.reasonCode)
    }

    @Test
    fun `agent profile with no allowedRules or deniedRules does not filter`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule-a", host = "*.example.com"),
                PolicyRule(id = "rule-b", host = "*.other.com")
            )
        )

        val profile = PolicyAgentProfile(id = "agent-8")

        val requestA = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val resultA = evaluatePolicyWithRule(policy, requestA, profile)
        assertEquals(PolicyAction.ALLOW, resultA.decision.action)
        assertEquals("rule-a", resultA.decision.ruleId)

        val requestB = PolicyRequest("https", "sub.other.com", 443, "GET", "/")
        val resultB = evaluatePolicyWithRule(policy, requestB, profile)
        assertEquals(PolicyAction.ALLOW, resultB.decision.action)
        assertEquals("rule-b", resultB.decision.ruleId)
    }

    @Test
    fun `matched rule is returned in PolicyMatch`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule-a", host = "*.example.com", methods = listOf("POST"))
            )
        )

        val profile = PolicyAgentProfile(id = "agent-9", allowedRules = listOf("rule-a"))

        val request = PolicyRequest("https", "api.example.com", 443, "POST", "/data")
        val result = evaluatePolicyWithRule(policy, request, profile)

        assertEquals(PolicyAction.ALLOW, result.decision.action)
        assertEquals("rule-a", result.rule?.id)
        assertEquals(listOf("POST"), result.rule?.methods)
    }
}
