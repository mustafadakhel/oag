package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.policy.core.PolicyResponseRewrite

internal class PolicyRedactionStep(
    private val rewrites: List<PolicyResponseRewrite>
) : ResponseInspectionStep {

    override fun inspect(bodyText: String, context: BufferedInspectionContext): StepOutcome {
        val result = applyPolicyRedactions(bodyText, rewrites, context.onError)
        context.accumulator.redactionActions.addAll(result.actions)
        context.accumulator.auditEntries.addAll(result.auditEntries)
        return StepOutcome.Continue(result.transformedText)
    }
}
