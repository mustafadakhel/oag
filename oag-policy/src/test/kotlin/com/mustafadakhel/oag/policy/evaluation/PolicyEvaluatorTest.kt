package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyCondition
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyHeaderMatch
import com.mustafadakhel.oag.policy.core.PolicyQueryMatch
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.ReasonCode

import kotlin.test.Test
import kotlin.test.assertEquals

class PolicyEvaluatorTest {
    @Test
    fun `deny rule takes precedence over allow rule`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "allow", host = "api.example.com", methods = listOf("GET"))
            ),
            deny = listOf(
                PolicyRule(id = "deny", host = "api.example.com", methods = listOf("GET"))
            )
        )

        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val decision = evaluatePolicy(policy, request)

        assertEquals(PolicyAction.DENY, decision.action)
        assertEquals("deny", decision.ruleId)
    }

    @Test
    fun `condition scheme matches when request scheme equals`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "https_only",
                    host = "api.example.com",
                    conditions = PolicyCondition(scheme = "https")
                )
            )
        )

        val httpsRequest = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, httpsRequest).action)

        val httpRequest = PolicyRequest("http", "api.example.com", 80, "GET", "/")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, httpRequest).action)
    }

    @Test
    fun `condition scheme match is case insensitive`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "https_only",
                    host = "api.example.com",
                    conditions = PolicyCondition(scheme = "HTTPS")
                )
            )
        )

        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, request).action)
    }

    @Test
    fun `condition ports matches when request port is in list`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "standard_ports",
                    host = "api.example.com",
                    conditions = PolicyCondition(ports = listOf(443, 8443))
                )
            )
        )

        val match443 = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, match443).action)

        val match8443 = PolicyRequest("https", "api.example.com", 8443, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, match8443).action)

        val noMatch = PolicyRequest("https", "api.example.com", 9090, "GET", "/")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, noMatch).action)
    }

    @Test
    fun `condition scheme and ports combined`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "secure_only",
                    host = "api.example.com",
                    conditions = PolicyCondition(scheme = "https", ports = listOf(443))
                )
            )
        )

        val goodRequest = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, goodRequest).action)

        val wrongScheme = PolicyRequest("http", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, wrongScheme).action)

        val wrongPort = PolicyRequest("https", "api.example.com", 8080, "GET", "/")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, wrongPort).action)
    }

    @Test
    fun `deny rule with conditions restricts specific port`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(action = PolicyAction.ALLOW),
            deny = listOf(
                PolicyRule(
                    id = "block_http",
                    host = "api.example.com",
                    conditions = PolicyCondition(scheme = "http")
                )
            )
        )

        val httpRequest = PolicyRequest("http", "api.example.com", 80, "GET", "/")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, httpRequest).action)

        val httpsRequest = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, httpsRequest).action)
    }

    @Test
    fun `null conditions do not affect matching`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "no_cond", host = "api.example.com", conditions = null)
            )
        )

        val request = PolicyRequest("http", "api.example.com", 9999, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, request).action)
    }

    @Test
    fun `custom reason code on allow rule is carried through`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "custom_allow",
                    host = "api.example.com",
                    reasonCode = "approved_by_security_team"
                )
            )
        )

        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val decision = evaluatePolicy(policy, request)

        assertEquals(PolicyAction.ALLOW, decision.action)
        assertEquals("approved_by_security_team", decision.customReasonCode)
        assertEquals("approved_by_security_team", decision.effectiveReasonCode())
    }

    @Test
    fun `custom reason code on deny rule is carried through`() {
        val policy = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(
                    id = "custom_deny",
                    host = "api.example.com",
                    reasonCode = "blocked_by_compliance"
                )
            )
        )

        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val decision = evaluatePolicy(policy, request)

        assertEquals(PolicyAction.DENY, decision.action)
        assertEquals("blocked_by_compliance", decision.customReasonCode)
        assertEquals("blocked_by_compliance", decision.effectiveReasonCode())
    }

    @Test
    fun `null custom reason code falls back to built-in code`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "no_custom", host = "api.example.com", reasonCode = null)
            )
        )

        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        val decision = evaluatePolicy(policy, request)

        assertEquals(PolicyAction.ALLOW, decision.action)
        assertEquals(null, decision.customReasonCode)
        assertEquals("allowed_by_rule", decision.effectiveReasonCode())
    }

    @Test
    fun `body match allows when body contains required content`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "body_rule",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch(contains = listOf("model"))
                )
            )
        )

        val match = PolicyRequest("https", "api.example.com", 443, "POST", "/v1/chat", body = """{"model":"gpt-4"}""")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, match).action)
    }

    @Test
    fun `body match denies when body lacks required content`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "body_rule",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch(contains = listOf("model"))
                )
            )
        )

        val noMatch = PolicyRequest("https", "api.example.com", 443, "POST", "/v1/chat", body = """{"prompt":"hello"}""")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, noMatch).action)
        assertEquals(ReasonCode.NO_MATCH_DEFAULT_DENY, evaluatePolicy(policy, noMatch).reasonCode)
    }

    @Test
    fun `body match skipped when body is null and rule has bodyMatch`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "body_rule",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch(contains = listOf("model"))
                )
            )
        )

        val noBody = PolicyRequest("https", "api.example.com", 443, "POST", "/v1/chat", body = null)
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, noBody).action)
    }

    @Test
    fun `body match with pattern regex works in evaluator`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "pattern_rule",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch(patterns = listOf("gpt-[34]"))
                )
            )
        )

        val match = PolicyRequest("https", "api.example.com", 443, "POST", "/", body = "use gpt-4 model")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, match).action)

        val noMatch = PolicyRequest("https", "api.example.com", 443, "POST", "/", body = "use gpt-5 model")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, noMatch).action)
    }

    @Test
    fun `null bodyMatch does not affect matching`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "no_body", host = "api.example.com", bodyMatch = null)
            )
        )

        val request = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, request).action)
    }

    @Test
    fun `empty ports list does not affect matching`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "empty_ports",
                    host = "api.example.com",
                    conditions = PolicyCondition(ports = emptyList())
                )
            )
        )

        val request = PolicyRequest("https", "api.example.com", 12345, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, request).action)
    }

    @Test
    fun `header_match with value matches case-insensitively`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "with_header",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "X-Api-Key", value = "secret123")
                    )
                )
            )
        )

        val matching = PolicyRequest("https", "api.example.com", 443, "GET", "/", headers = mapOf("x-api-key" to "SECRET123"))
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, matching).action)

        val noHeader = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, noHeader).action)
    }

    @Test
    fun `header_match with present true requires header exists`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "present_check",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "Authorization", present = true)
                    )
                )
            )
        )

        val withAuth = PolicyRequest("https", "api.example.com", 443, "GET", "/", headers = mapOf("Authorization" to "Bearer tok"))
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, withAuth).action)

        val noAuth = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, noAuth).action)
    }

    @Test
    fun `header_match with present false requires header absent`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "absent_check",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "X-Debug", present = false)
                    )
                )
            )
        )

        val noDebug = PolicyRequest("https", "api.example.com", 443, "GET", "/")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, noDebug).action)

        val withDebug = PolicyRequest("https", "api.example.com", 443, "GET", "/", headers = mapOf("X-Debug" to "true"))
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, withDebug).action)
    }

    @Test
    fun `header_match with pattern uses regex`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "pattern_check",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "Authorization", pattern = "^Bearer\\s+.+")
                    )
                )
            )
        )

        val bearer = PolicyRequest("https", "api.example.com", 443, "GET", "/", headers = mapOf("Authorization" to "Bearer mytoken"))
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, bearer).action)

        val basic = PolicyRequest("https", "api.example.com", 443, "GET", "/", headers = mapOf("Authorization" to "Basic abc"))
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, basic).action)
    }

    @Test
    fun `header_match with multiple conditions uses AND semantics`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "multi_header",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "X-Api-Key", present = true),
                        PolicyHeaderMatch(header = "X-Source", value = "agent")
                    )
                )
            )
        )

        val both = PolicyRequest("https", "api.example.com", 443, "GET", "/", headers = mapOf("X-Api-Key" to "key1", "X-Source" to "agent"))
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, both).action)

        val onlyKey = PolicyRequest("https", "api.example.com", 443, "GET", "/", headers = mapOf("X-Api-Key" to "key1"))
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, onlyKey).action)
    }

    @Test
    fun `query_match with value matches parameter`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "query_val",
                    host = "api.example.com",
                    queryMatch = listOf(
                        PolicyQueryMatch(param = "model", value = "gpt-4")
                    )
                )
            )
        )

        val matching = PolicyRequest("https", "api.example.com", 443, "GET", "/v1/chat?model=gpt-4")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, matching).action)

        val noMatch = PolicyRequest("https", "api.example.com", 443, "GET", "/v1/chat?model=gpt-3")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, noMatch).action)

        val noParam = PolicyRequest("https", "api.example.com", 443, "GET", "/v1/chat")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, noParam).action)
    }

    @Test
    fun `query_match with present true requires param exists`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "query_present",
                    host = "api.example.com",
                    queryMatch = listOf(
                        PolicyQueryMatch(param = "api_key", present = true)
                    )
                )
            )
        )

        val withKey = PolicyRequest("https", "api.example.com", 443, "GET", "/v1?api_key=abc")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, withKey).action)

        val noKey = PolicyRequest("https", "api.example.com", 443, "GET", "/v1")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, noKey).action)
    }

    @Test
    fun `query_match with present false denies when param is present`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "query_absent",
                    host = "api.example.com",
                    queryMatch = listOf(
                        PolicyQueryMatch(param = "debug", present = false)
                    )
                )
            )
        )

        val noDebug = PolicyRequest("https", "api.example.com", 443, "GET", "/v1")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, noDebug).action)

        val withDebug = PolicyRequest("https", "api.example.com", 443, "GET", "/v1?debug=true")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, withDebug).action)
    }

    @Test
    fun `query_match with multiple conditions uses AND semantics`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "multi_query",
                    host = "api.example.com",
                    queryMatch = listOf(
                        PolicyQueryMatch(param = "model", value = "gpt-4"),
                        PolicyQueryMatch(param = "stream", present = true)
                    )
                )
            )
        )

        val both = PolicyRequest("https", "api.example.com", 443, "GET", "/v1?model=gpt-4&stream=true")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, both).action)

        val onlyModel = PolicyRequest("https", "api.example.com", 443, "GET", "/v1?model=gpt-4")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, onlyModel).action)

        val onlyStream = PolicyRequest("https", "api.example.com", 443, "GET", "/v1?stream=true")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, onlyStream).action)

        val neither = PolicyRequest("https", "api.example.com", 443, "GET", "/v1")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, neither).action)
    }

    @Test
    fun `query_match with pattern uses regex`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "query_pattern",
                    host = "api.example.com",
                    queryMatch = listOf(
                        PolicyQueryMatch(param = "version", pattern = "^v[0-9]+$")
                    )
                )
            )
        )

        val v2 = PolicyRequest("https", "api.example.com", 443, "GET", "/api?version=v2")
        assertEquals(PolicyAction.ALLOW, evaluatePolicy(policy, v2).action)

        val invalid = PolicyRequest("https", "api.example.com", 443, "GET", "/api?version=latest")
        assertEquals(PolicyAction.DENY, evaluatePolicy(policy, invalid).action)
    }
}
