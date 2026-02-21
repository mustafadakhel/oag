package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.commands.DecisionRecord
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.app.commands.Outcome
import com.mustafadakhel.oag.app.commands.Reason
import com.mustafadakhel.oag.app.commands.ReasonCategory
import com.mustafadakhel.oag.app.commands.RuleRef
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCategory as PolicyReasonCategory
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

internal fun PolicyDecision.toDecisionRecord(): DecisionRecord = DecisionRecord(
    outcome = when (action) {
        PolicyAction.ALLOW -> Outcome.ALLOW
        PolicyAction.DENY -> Outcome.DENY
    },
    ruleRef = ruleId?.let { RuleRef(it) },
    findings = emptyList(),
    actionsApplied = when (action) {
        PolicyAction.DENY -> listOf(EnforcementAction.Deny(reason = effectiveReasonCode()))
        PolicyAction.ALLOW -> listOf(EnforcementAction.Allow)
    },
    reasons = listOf(
        Reason(
            code = effectiveReasonCode(),
            category = reasonCode.category.toEnforcementCategory()
        )
    ),
    timings = emptyMap()
)

internal fun formatExplainText(record: DecisionRecord): String {
    val action = record.outcome.label()
    val reason = record.primaryReason?.code ?: "-"
    val rule = record.ruleRef?.ruleId ?: "-"
    return "action=$action reason=$reason rule=$rule"
}

internal fun formatExplainJson(record: DecisionRecord, verbose: Boolean = false, request: RequestSummary? = null): String =
    cliJson.encodeToString(ExplainJsonOutput(
        action = record.outcome.label(),
        reasonCode = record.primaryReason?.code ?: "-",
        ruleId = record.ruleRef?.ruleId,
        request = if (verbose && request != null) request else null
    ))

@Serializable
internal data class ExplainJsonOutput(
    val ok: Boolean = true,
    val action: String,
    @SerialName("reason_code") val reasonCode: String,
    @SerialName("rule_id") val ruleId: String?,
    val request: RequestSummary? = null
)

private fun PolicyReasonCategory.toEnforcementCategory(): ReasonCategory =
    when (this) {
        PolicyReasonCategory.POLICY -> ReasonCategory.POLICY
        PolicyReasonCategory.NETWORK -> ReasonCategory.NETWORK
        PolicyReasonCategory.SECURITY -> ReasonCategory.SECURITY
        PolicyReasonCategory.VALIDATION -> ReasonCategory.VALIDATION
        PolicyReasonCategory.RESOURCE -> ReasonCategory.RESOURCE
    }
