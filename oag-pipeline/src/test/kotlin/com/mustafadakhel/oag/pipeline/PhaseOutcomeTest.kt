package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PhaseOutcomeTest {

    @Test
    fun `deny exposes enforcement action with reason and status`() {
        val deny = PhaseOutcome.Deny(
            decision = PolicyDecision(PolicyAction.DENY, "rule-1", ReasonCode.DENIED_BY_RULE),
            statusCode = HttpStatus.FORBIDDEN
        )
        val action = deny.enforcementAction
        assertIs<EnforcementAction.Deny>(action)
        assertEquals("denied_by_rule", action.reason)
        assertEquals(403, action.statusCode)
    }

    @Test
    fun `deny with custom reason code uses it in enforcement action`() {
        val deny = PhaseOutcome.Deny(
            decision = PolicyDecision(PolicyAction.DENY, null, ReasonCode.DENIED_BY_RULE, customReasonCode = "custom_block"),
            statusCode = HttpStatus.TOO_MANY_REQUESTS
        )
        assertEquals("custom_block", deny.enforcementAction.reason)
        assertEquals(429, deny.enforcementAction.statusCode)
    }

    @Test
    fun `deny with different status codes maps correctly`() {
        val deny502 = PhaseOutcome.Deny(
            decision = PolicyDecision(PolicyAction.DENY, null, ReasonCode.UPSTREAM_CONNECTION_FAILED),
            statusCode = HttpStatus.BAD_GATEWAY
        )
        assertEquals(502, deny502.enforcementAction.statusCode)
        assertEquals("upstream_connection_failed", deny502.enforcementAction.reason)
    }

    @Test
    fun `deny carries enforcement actions list`() {
        val deny = PhaseOutcome.Deny(
            decision = PolicyDecision(PolicyAction.DENY, null, ReasonCode.INJECTION_DETECTED),
            statusCode = HttpStatus.FORBIDDEN,
            enforcementActions = listOf(
                EnforcementAction.Notify(message = "injection_detected")
            )
        )
        assertEquals(1, deny.enforcementActions.size)
        assertIs<EnforcementAction.Notify>(deny.enforcementActions.first())
        assertEquals("injection_detected", (deny.enforcementActions.first() as EnforcementAction.Notify).message)
    }

    @Test
    fun `deny defaults to empty enforcement actions`() {
        val deny = PhaseOutcome.Deny(
            decision = PolicyDecision(PolicyAction.DENY, null, ReasonCode.DENIED_BY_RULE),
            statusCode = HttpStatus.FORBIDDEN
        )
        assertTrue(deny.enforcementActions.isEmpty())
    }
}
