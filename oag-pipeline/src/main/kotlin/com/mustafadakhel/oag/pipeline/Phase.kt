package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.StageSet
import com.mustafadakhel.oag.validateStageOrder

class Pipeline(
    val name: String,
    val phases: List<Phase>,
    val stageSet: StageSet = StageSet.ALL
) {
    init {
        validateStageOrder(phases.map { it.name to it.stage }, stageSet)
        validateSkipDependencies(phases)
    }

    suspend fun run(context: RequestPipelineContext) {
        for (phase in phases) {
            if (phase.skipWhenPolicyDenied && context.policyDenied) {
                if (phase is AuditEnrichable) phase.enrichAudit(context)
                continue
            }
            phase.execute(context)
        }
    }

    fun phaseNames(): List<String> = phases.map { it.name }

    val phaseCount: Int get() = phases.size

    fun filterByStageSet(stageSet: StageSet) =
        Pipeline(name = name, phases = phases.filter { it.stage in stageSet }, stageSet = stageSet)
}

interface Phase {
    val name: String
    val stage: PipelineStage get() = PipelineStage.ACTIONS
    val skipWhenPolicyDenied: Boolean get() = false
    val producesKeys: Set<PhaseKey<*>> get() = emptySet()
    suspend fun execute(context: RequestPipelineContext)
}

interface GatePhase : Phase {
    fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit>
    override suspend fun execute(context: RequestPipelineContext) {
        evaluate(context).orDenyDryRunnable(context)
    }
}

interface MutationPhase : Phase {
    fun mutate(context: RequestPipelineContext)
    override suspend fun execute(context: RequestPipelineContext) = mutate(context)
}

/**
 * Opt-in interface for phases that can enrich audit data when skipped due to policy denial.
 * When [Phase.skipWhenPolicyDenied] causes a phase to be skipped, [Pipeline.run] calls
 * [enrichAudit] instead of [Phase.execute] — collecting sensor data for the audit trail
 * without making enforcement decisions.
 */
interface AuditEnrichable {
    fun enrichAudit(context: RequestPipelineContext)
}

private fun validateSkipDependencies(phases: List<Phase>) {
    if (phases.none { it.skipWhenPolicyDenied }) return
    val policyEvalIndex = phases.indexOfFirst { PolicyEvalKey in it.producesKeys }
    require(policyEvalIndex >= 0) {
        "Pipeline has phases with skipWhenPolicyDenied but no phase produces PolicyEvalKey"
    }
    for ((index, phase) in phases.withIndex()) {
        if (phase.skipWhenPolicyDenied) {
            require(index > policyEvalIndex) {
                "Phase '${phase.name}' has skipWhenPolicyDenied=true but appears at index $index, " +
                    "before the policy evaluation phase at index $policyEvalIndex"
            }
        }
    }
}

