package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.inspection.Finding

data class DecisionRecord(
    val outcome: Outcome,
    val ruleRef: RuleRef?,
    val findings: List<Finding>,
    val actionsApplied: List<EnforcementAction>,
    val reasons: List<Reason>,
    val timings: Map<String, Long>
) {
    val allowed: Boolean get() = outcome == Outcome.ALLOW
    val primaryReason: Reason? get() = reasons.firstOrNull()
}

enum class Outcome {
    ALLOW,
    DENY

}

data class RuleRef(
    val ruleId: String,
    val policyHash: String? = null
)

data class Reason(
    val code: String,
    val category: ReasonCategory,
    val message: String? = null
)

enum class ReasonCategory {
    POLICY,
    NETWORK,
    SECURITY,
    VALIDATION,
    RESOURCE

}
