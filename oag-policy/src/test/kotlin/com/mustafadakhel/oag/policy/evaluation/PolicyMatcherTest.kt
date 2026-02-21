package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PolicyMatcherTest {
    @Test
    fun `wildcard host matches subdomain only`() {
        val rule = PolicyRule(id = "r1", host = "*.example.com")
        val requestOk = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val requestNo = PolicyRequest("https", "example.com", 443, "GET", "/")

        assertEquals(PolicyAction.ALLOW, evaluatePolicyWithRule(PolicyDocument(version = 1, allow = listOf(rule)), requestOk).decision.action)
        assertEquals(PolicyAction.DENY, evaluatePolicyWithRule(PolicyDocument(version = 1, allow = listOf(rule)), requestNo).decision.action)
    }

    @Test
    fun `path glob matches nested routes`() {
        val rule = PolicyRule(id = "r1", host = "api.example.com", paths = listOf("/v1/*"))
        val request = PolicyRequest("https", "api.example.com", 443, "POST", "/v1/chat/completions")

        assertEquals(PolicyAction.ALLOW, evaluatePolicyWithRule(PolicyDocument(version = 1, allow = listOf(rule)), request).decision.action)
    }

    @Test
    fun `path glob handles consecutive wildcards and anchored literals`() {
        val rule = PolicyRule(id = "r1", host = "api.example.com", paths = listOf("/v1/**/models*"))
        val allowRequest = PolicyRequest("https", "api.example.com", 443, "GET", "/v1/a/b/models-2026")
        val denyRequest = PolicyRequest("https", "api.example.com", 443, "GET", "/v2/a/b/models-2026")

        val policy = PolicyDocument(version = 1, allow = listOf(rule))
        assertEquals(PolicyAction.ALLOW, evaluatePolicyWithRule(policy, allowRequest).decision.action)
        assertEquals(PolicyAction.DENY, evaluatePolicyWithRule(policy, denyRequest).decision.action)
    }

    @Test
    fun `host and method matching are case insensitive after normalization`() {
        val rule = PolicyRule(id = "r1", host = "API.Example.Com", methods = listOf("post"), paths = listOf("/v1/*"))
        val request = PolicyRequest("https", "api.example.com", 443, "POST", "/v1/chat")
        val policy = PolicyDocument(version = 1, allow = listOf(rule))

        assertEquals(PolicyAction.ALLOW, evaluatePolicyWithRule(policy, request).decision.action)
    }

    @Test
    fun `host match ignores trailing dot on request`() {
        val rule = PolicyRule(id = "r1", host = "api.example.com")
        val request = PolicyRequest("https", "api.example.com.", 443, "GET", "/")
        val policy = PolicyDocument(version = 1, allow = listOf(rule))

        assertEquals(PolicyAction.ALLOW, evaluatePolicyWithRule(policy, request).decision.action)
    }

    @Test
    fun `host match ignores trailing dot on rule`() {
        val rule = PolicyRule(id = "r1", host = "api.example.com.")
        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val policy = PolicyDocument(version = 1, allow = listOf(rule))

        assertEquals(PolicyAction.ALLOW, evaluatePolicyWithRule(policy, request).decision.action)
    }

    @Test
    fun `wildcard path matches across slash boundaries`() {
        val rule = PolicyRule(id = "r1", host = "api.example.com", paths = listOf("/v1/*/completions"))
        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/v1/chat/stream/completions")
        val policy = PolicyDocument(version = 1, allow = listOf(rule))

        assertEquals(PolicyAction.ALLOW, evaluatePolicyWithRule(policy, request).decision.action)
    }

    @Test
    fun `ip range rule matches ip literal host`() {
        val rule = PolicyRule(id = "r1", host = "10.0.0.1", ipRanges = listOf("10.0.0.0/24"))
        val request = PolicyRequest("https", "10.0.0.1", 443, "GET", "/")
        val policy = PolicyDocument(version = 1, allow = listOf(rule))

        assertEquals(PolicyAction.ALLOW, evaluatePolicyWithRule(policy, request).decision.action)
    }

    @Test
    fun `ip range rule does not match hostname`() {
        val rule = PolicyRule(id = "r1", host = "api.example.com", ipRanges = listOf("10.0.0.0/24"))
        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val policy = PolicyDocument(version = 1, allow = listOf(rule))

        assertEquals(PolicyAction.DENY, evaluatePolicyWithRule(policy, request).decision.action)
    }
}
