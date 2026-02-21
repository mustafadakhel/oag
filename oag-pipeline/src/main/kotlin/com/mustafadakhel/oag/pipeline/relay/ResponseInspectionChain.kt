package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.policy.core.PolicyRule

internal class ResponseInspectionChain(private val steps: List<ResponseInspectionStep>) {

    fun run(bodyText: String, context: BufferedInspectionContext): StepOutcome {
        var current = bodyText
        for (step in steps) {
            when (val outcome = step.inspect(current, context)) {
                is StepOutcome.Continue -> current = outcome.bodyText
                is StepOutcome.Deny -> return outcome
            }
        }
        return StepOutcome.Continue(current)
    }
}

internal fun buildInspectionChain(
    plan: ResponseInspectionPlan,
    matchedRule: PolicyRule?,
    detectorRegistry: DetectorRegistry
): ResponseInspectionChain {
    val steps = buildList<ResponseInspectionStep> {
        if (plan.redact) {
            add(PolicyRedactionStep(requireNotNull(matchedRule?.responseRewrites)))
        }
        if (plan.bodyMatch != null) {
            add(BodyMatchGateStep(plan.bodyMatch))
        }
        if (plan.dataClassification != null) {
            add(DataClassificationStep(plan.dataClassification))
        }
        if (plan.pluginScan) {
            add(PluginScanStep(detectorRegistry))
        }
    }
    return ResponseInspectionChain(steps)
}
