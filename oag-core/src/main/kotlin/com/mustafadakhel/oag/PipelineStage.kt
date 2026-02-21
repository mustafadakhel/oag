package com.mustafadakhel.oag

enum class PipelineStage {
    IDENTITY,
    TARGET,
    POLICY,
    INSPECT,
    ACTIONS
}

data class StageSet(val stages: Set<PipelineStage>) {
    operator fun contains(stage: PipelineStage): Boolean = stage in stages

    companion object {
        val ALL = StageSet(PipelineStage.entries.toSet())

        val REQUEST = StageSet(setOf(
            PipelineStage.IDENTITY,
            PipelineStage.TARGET,
            PipelineStage.POLICY,
            PipelineStage.INSPECT,
            PipelineStage.ACTIONS
        ))

        val CONNECT = StageSet(setOf(
            PipelineStage.IDENTITY,
            PipelineStage.TARGET,
            PipelineStage.POLICY,
            PipelineStage.ACTIONS
        ))
    }
}

fun validateStageOrder(phases: List<Pair<String, PipelineStage>>, stageSet: StageSet) {
    var lastOrdinal = -1
    for ((name, stage) in phases) {
        val ordinal = stage.ordinal
        require(ordinal >= lastOrdinal) {
            "Phase '$name' (stage $stage) appears after a later stage — expected non-decreasing stage order"
        }
        require(stage in stageSet) {
            "Phase '$name' declares stage $stage which is not in the pipeline's stage set"
        }
        lastOrdinal = ordinal
    }
}
