package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.commands.DecisionRecord
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.app.commands.Outcome
import com.mustafadakhel.oag.app.commands.Reason
import com.mustafadakhel.oag.app.commands.ReasonCategory
import com.mustafadakhel.oag.app.commands.RuleRef
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DecisionRecordProjectionTest {

    @Test
    fun `ALLOW PolicyDecision maps to ALLOW Outcome`() {
        val decision = PolicyDecision(PolicyAction.ALLOW, "rule-1", ReasonCode.ALLOWED_BY_RULE)
        val record = decision.toDecisionRecord()
        assertEquals(Outcome.ALLOW, record.outcome)
        assertTrue(record.allowed)
    }

    @Test
    fun `DENY PolicyDecision maps to DENY Outcome`() {
        val decision = PolicyDecision(PolicyAction.DENY, null, ReasonCode.NO_MATCH_DEFAULT_DENY)
        val record = decision.toDecisionRecord()
        assertEquals(Outcome.DENY, record.outcome)
        assertFalse(record.allowed)
    }

    @Test
    fun `ruleId maps to RuleRef`() {
        val decision = PolicyDecision(PolicyAction.ALLOW, "rule-1", ReasonCode.ALLOWED_BY_RULE)
        val record = decision.toDecisionRecord()
        assertEquals("rule-1", record.ruleRef?.ruleId)
    }

    @Test
    fun `null ruleId maps to null ruleRef`() {
        val decision = PolicyDecision(PolicyAction.DENY, null, ReasonCode.NO_MATCH_DEFAULT_DENY)
        val record = decision.toDecisionRecord()
        assertNull(record.ruleRef)
    }

    @Test
    fun `reasonCode maps to Reason with correct category`() {
        val decision = PolicyDecision(PolicyAction.DENY, null, ReasonCode.RATE_LIMITED)
        val record = decision.toDecisionRecord()
        assertEquals(1, record.reasons.size)
        assertEquals("rate_limited", record.reasons[0].code)
        assertEquals(ReasonCategory.RESOURCE, record.reasons[0].category)
    }

    @Test
    fun `customReasonCode is used when present`() {
        val decision = PolicyDecision(PolicyAction.DENY, "rule-1", ReasonCode.DENIED_BY_RULE, customReasonCode = "custom_block")
        val record = decision.toDecisionRecord()
        assertEquals("custom_block", record.reasons[0].code)
    }

    @Test
    fun `findings are empty and actionsApplied reflects decision from PolicyDecision`() {
        val decision = PolicyDecision(PolicyAction.ALLOW, null, ReasonCode.NO_MATCH_DEFAULT_ALLOW)
        val record = decision.toDecisionRecord()
        assertTrue(record.findings.isEmpty())
        assertEquals(1, record.actionsApplied.size)
        assertIs<EnforcementAction.Allow>(record.actionsApplied.first())
    }

    @Test
    fun `formatExplainText produces correct output`() {
        val record = DecisionRecord(
            outcome = Outcome.ALLOW,
            ruleRef = RuleRef("rule-1"),
            findings = emptyList(),
            actionsApplied = emptyList(),
            reasons = listOf(Reason("allowed_by_rule", ReasonCategory.POLICY)),
            timings = emptyMap()
        )
        assertEquals("action=allow reason=allowed_by_rule rule=rule-1", formatExplainText(record))
    }

    @Test
    fun `formatExplainText with no rule shows dash`() {
        val record = DecisionRecord(
            outcome = Outcome.DENY,
            ruleRef = null,
            findings = emptyList(),
            actionsApplied = emptyList(),
            reasons = listOf(Reason("no_match_default_deny", ReasonCategory.POLICY)),
            timings = emptyMap()
        )
        assertEquals("action=deny reason=no_match_default_deny rule=-", formatExplainText(record))
    }

    @Test
    fun `formatExplainJson includes action reason and rule`() {
        val record = DecisionRecord(
            outcome = Outcome.ALLOW,
            ruleRef = RuleRef("rule-1"),
            findings = emptyList(),
            actionsApplied = emptyList(),
            reasons = listOf(Reason("allowed_by_rule", ReasonCategory.POLICY)),
            timings = emptyMap()
        )
        val json = formatExplainJson(record)
        assertContains(json, "\"action\":\"allow\"")
        assertContains(json, "\"reason_code\":\"allowed_by_rule\"")
        assertContains(json, "\"rule_id\":\"rule-1\"")
    }

    @Test
    fun `formatExplainJson verbose includes request info`() {
        val record = DecisionRecord(
            outcome = Outcome.ALLOW,
            ruleRef = null,
            findings = emptyList(),
            actionsApplied = emptyList(),
            reasons = listOf(Reason("allowed_by_rule", ReasonCategory.POLICY)),
            timings = emptyMap()
        )
        val requestInfo = RequestSummary("https", "api.example.com", 443, "GET", "/v1/chat")
        val json = formatExplainJson(record, verbose = true, request = requestInfo)
        assertContains(json, "\"scheme\":\"https\"")
        assertContains(json, "\"host\":\"api.example.com\"")
        assertContains(json, "\"port\":443")
        assertContains(json, "\"method\":\"GET\"")
        assertContains(json, "\"path\":\"/v1/chat\"")
    }

    @Test
    fun `formatExplainJson non-verbose omits request info`() {
        val record = DecisionRecord(
            outcome = Outcome.ALLOW,
            ruleRef = null,
            findings = emptyList(),
            actionsApplied = emptyList(),
            reasons = listOf(Reason("ok", ReasonCategory.POLICY)),
            timings = emptyMap()
        )
        val json = formatExplainJson(record, verbose = false)
        assertTrue(!json.contains("\"scheme\""))
        assertTrue(!json.contains("\"host\""))
    }

    @Test
    fun `all ReasonCategory values map correctly`() {
        val mappings = mapOf(
            ReasonCode.DENIED_BY_RULE to ReasonCategory.POLICY,
            ReasonCode.RAW_IP_LITERAL_BLOCKED to ReasonCategory.NETWORK,
            ReasonCode.INJECTION_DETECTED to ReasonCategory.SECURITY,
            ReasonCode.BODY_TOO_LARGE to ReasonCategory.VALIDATION,
            ReasonCode.RATE_LIMITED to ReasonCategory.RESOURCE
        )
        for ((reasonCode, expectedCategory) in mappings) {
            val decision = PolicyDecision(PolicyAction.DENY, null, reasonCode)
            val record = decision.toDecisionRecord()
            assertEquals(expectedCategory, record.reasons[0].category, "Failed for $reasonCode")
        }
    }
}
