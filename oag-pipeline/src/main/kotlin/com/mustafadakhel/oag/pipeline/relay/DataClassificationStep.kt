package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.policy.core.PolicyDataClassification

internal class DataClassificationStep(
    private val dataClassification: PolicyDataClassification
) : ResponseInspectionStep {

    override fun inspect(bodyText: String, context: BufferedInspectionContext): StepOutcome {
        context.accumulator.dataClassification =
            runResponseDataClassification(bodyText, dataClassification, context.onError)
        return StepOutcome.Continue(bodyText)
    }
}
