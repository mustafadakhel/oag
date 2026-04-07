package com.mustafadakhel.oag.inspection

import com.mustafadakhel.oag.FindingSeverity
import com.mustafadakhel.oag.FindingType

data class Finding(
    val type: FindingType,
    val severity: FindingSeverity,
    val confidence: Double,
    val location: FindingLocation?,
    val evidence: Map<String, String>,
    val recommendedActions: List<RecommendedAction>
)
