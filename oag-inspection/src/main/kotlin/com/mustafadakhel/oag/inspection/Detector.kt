package com.mustafadakhel.oag.inspection

fun interface Detector<T : InspectableArtifact> {
    fun inspect(input: T, ctx: InspectionContext): List<Finding>
}

data class InspectionContext(
    val host: String? = null,
    val method: String? = null,
    val path: String? = null,
    val ruleId: String? = null,
    val agentId: String? = null
)
