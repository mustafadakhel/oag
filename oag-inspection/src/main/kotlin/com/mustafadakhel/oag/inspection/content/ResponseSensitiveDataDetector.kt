package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.inspection.EvidenceKey
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.RedactingDetector
import com.mustafadakhel.oag.inspection.RedactionPattern
import com.mustafadakhel.oag.inspection.ResponseTextBody

class ResponseSensitiveDataDetector(
    private val categories: List<String>? = null
) : RedactingDetector<ResponseTextBody> {

    override fun inspect(input: ResponseTextBody, ctx: InspectionContext): List<Finding> {
        val byCategory = SensitiveDataPatterns.matchesByCategory(input.text, categories)
        return byCategory.flatMap { (category, patterns) ->
            patterns.map { pattern ->
                Finding(
                    type = FindingType.PII,
                    severity = FindingSeverity.HIGH,
                    confidence = 0.9,
                    location = FindingLocation.Body,
                    evidence = mapOf(EvidenceKey.CATEGORY to category, EvidenceKey.PATTERN to pattern),
                    recommendedActions = listOf(RecommendedAction.REDACT, RecommendedAction.LOG)
                )
            }
        }
    }

    override fun redactionPatterns(input: ResponseTextBody, ctx: InspectionContext): List<RedactionPattern> =
        SensitiveDataPatterns.patternsForCategories(categories)
            .filter { it.regex.containsMatchIn(input.text) }
            .map { RedactionPattern(name = it.name, regex = it.regex) }
}
