package com.mustafadakhel.oag.inspection

import com.mustafadakhel.oag.REDACTED_SENTINEL

data class RedactionPattern(
    val name: String,
    val regex: Regex,
    val replacement: String = REDACTED_SENTINEL
)

interface RedactingDetector<T : InspectableArtifact> : Detector<T> {
    fun redactionPatterns(input: T, ctx: InspectionContext): List<RedactionPattern>
}
