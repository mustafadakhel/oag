package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.inspection.EvidenceKey
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.PatternEntry
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.RedactingDetector
import com.mustafadakhel.oag.inspection.RedactionPattern
import com.mustafadakhel.oag.inspection.ResponseTextBody

class ResponseCredentialDetector(
    private val patterns: List<PatternEntry> = CredentialPatterns.ALL
) : RedactingDetector<ResponseTextBody> {

    override fun inspect(input: ResponseTextBody, ctx: InspectionContext): List<Finding> =
        patterns
            .filter { it.regex.containsMatchIn(input.text) }
            .map { pattern ->
                Finding(
                    type = FindingType.CREDENTIAL,
                    severity = FindingSeverity.CRITICAL,
                    confidence = 0.95,
                    location = FindingLocation.Body,
                    evidence = mapOf(EvidenceKey.PATTERN to pattern.name),
                    recommendedActions = listOf(RecommendedAction.REDACT)
                )
            }

    override fun redactionPatterns(input: ResponseTextBody, ctx: InspectionContext): List<RedactionPattern> =
        patterns
            .filter { it.regex.containsMatchIn(input.text) }
            .map { RedactionPattern(name = it.name, regex = it.regex) }
}
