package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode

internal class BodyMatchGateStep(
    private val bodyMatch: PolicyBodyMatch
) : ResponseInspectionStep {

    override fun inspect(bodyText: String, context: BufferedInspectionContext): StepOutcome {
        if (!evaluateBodyMatch(bodyText, bodyMatch, context.onError)) {
            return StepOutcome.Deny(
                PolicyDecision(
                    action = PolicyAction.DENY,
                    ruleId = context.matchedRule?.id,
                    reasonCode = ReasonCode.RESPONSE_INJECTION_DETECTED
                )
            )
        }
        return StepOutcome.Continue(bodyText)
    }
}
