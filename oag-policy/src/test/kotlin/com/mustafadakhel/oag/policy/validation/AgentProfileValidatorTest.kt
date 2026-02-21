package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicyAgentProfile
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyRule
import kotlin.test.Test
import kotlin.test.assertTrue

class AgentProfileValidatorTest {

    private fun validate(profiles: List<PolicyAgentProfile>, rules: List<PolicyRule> = emptyList()) =
        validateAgentProfiles(PolicyDocument(version = 1, agentProfiles = profiles, allow = rules))

    @Test
    fun `blank id produces error`() {
        val errors = validate(listOf(PolicyAgentProfile(id = "")))
        assertTrue(errors.any { it.path.contains("id") })
    }

    @Test
    fun `whitespace in id produces error`() {
        val errors = validate(listOf(PolicyAgentProfile(id = "agent one")))
        assertTrue(errors.any { it.path.contains("id") })
    }

    @Test
    fun `duplicate ids produce error`() {
        val errors = validate(listOf(
            PolicyAgentProfile(id = "agent-1"),
            PolicyAgentProfile(id = "agent-1")
        ))
        assertTrue(errors.any { it.message.contains("Duplicate") })
    }

    @Test
    fun `both allowedRules and deniedRules produces error`() {
        val rules = listOf(PolicyRule(id = "r1", host = "*.example.com"))
        val errors = validate(
            listOf(PolicyAgentProfile(id = "a", allowedRules = listOf("r1"), deniedRules = listOf("r1"))),
            rules
        )
        assertTrue(errors.any { it.message.contains("Cannot set both") })
    }

    @Test
    fun `non-positive maxRequestsPerMinute produces error`() {
        val errors = validate(listOf(PolicyAgentProfile(id = "a", maxRequestsPerMinute = 0)))
        assertTrue(errors.any { it.path.contains("max_requests_per_minute") })
    }

    @Test
    fun `unknown rule reference produces error`() {
        val errors = validate(
            listOf(PolicyAgentProfile(id = "a", allowedRules = listOf("nonexistent"))),
            listOf(PolicyRule(id = "r1", host = "*.example.com"))
        )
        assertTrue(errors.any { it.message.contains("unknown rule") })
    }

    @Test
    fun `valid profile produces no errors`() {
        val rules = listOf(PolicyRule(id = "r1", host = "*.example.com"))
        val errors = validate(listOf(PolicyAgentProfile(id = "agent-1", allowedRules = listOf("r1"))), rules)
        assertTrue(errors.isEmpty())
    }
}
