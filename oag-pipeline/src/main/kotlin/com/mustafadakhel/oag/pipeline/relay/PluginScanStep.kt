package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.inspection.spi.DetectorRegistry

internal class PluginScanStep(
    private val detectorRegistry: DetectorRegistry
) : ResponseInspectionStep {

    override fun inspect(bodyText: String, context: BufferedInspectionContext): StepOutcome {
        val pluginFindings = runResponsePluginScan(
            bodyText = bodyText,
            statusCode = context.statusCode,
            contentType = context.contentType,
            ruleHost = context.matchedRule?.host,
            ruleId = context.matchedRule?.id,
            registry = detectorRegistry,
            onError = context.onError
        )
        context.accumulator.pluginFindings = pluginFindings

        if (pluginFindings.redactionPatterns.isNotEmpty()) {
            val redactionResult = applyFindingRedactions(bodyText, pluginFindings.redactionPatterns)
            context.accumulator.redactionActions.addAll(redactionResult.actions)
            return StepOutcome.Continue(redactionResult.transformedText)
        }

        return StepOutcome.Continue(bodyText)
    }
}
