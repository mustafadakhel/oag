package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.audit.AuditResponseRewrite
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.pipeline.inspection.DataClassificationResult
import com.mustafadakhel.oag.pipeline.inspection.ResponseScanResult
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyRule

/**
 * A composable inspection step for buffered response processing.
 * Steps run sequentially; each receives the (possibly mutated) body text
 * from the previous step and may further modify it or short-circuit with deny.
 *
 * Design note: This uses a simpler structure than the request-side [com.mustafadakhel.oag.pipeline.Phase]
 * contract (no stage ordering, no named identity, non-generic outcome, fixed-schema accumulator
 * instead of type-safe PhaseKey map). The response chain has 3–4 steps vs 28 request phases —
 * the simpler design is pragmatic for the current step count. If the chain grows past 5–6 steps,
 * consider unifying to a PhaseKey-based ResponsePhaseOutputs model with stage ordering.
 */
fun interface ResponseInspectionStep {
    fun inspect(bodyText: String, context: BufferedInspectionContext): StepOutcome
}

sealed class StepOutcome {
    data class Continue(val bodyText: String) : StepOutcome()
    data class Deny(val decision: PolicyDecision) : StepOutcome()
}

class BufferedInspectionContext(
    val statusCode: Int,
    val contentType: String?,
    val matchedRule: PolicyRule?,
    val onError: (String) -> Unit,
    val accumulator: InspectionAccumulator = InspectionAccumulator()
)

/**
 * Collects side-effect data from inspection steps.
 * Conceptually mirrors [com.mustafadakhel.oag.pipeline.PhaseOutputs] but uses named fields
 * instead of a type-safe key map — appropriate while the step count is small.
 */
class InspectionAccumulator {
    val redactionActions: MutableList<EnforcementAction.Redact> = mutableListOf()
    val auditEntries: MutableList<AuditResponseRewrite> = mutableListOf()
    var dataClassification: DataClassificationResult? = null
    var pluginFindings: ResponseScanResult? = null
}
