package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.inspection.PatternEntry
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.SensitiveDataCategory

object SensitiveDataPatterns {

    val FINANCIAL: List<PatternEntry> = listOf(
        PatternEntry("credit_card_visa", Regex("""\b4[0-9]{12}(?:[0-9]{3})?\b""")),
        PatternEntry("credit_card_mastercard", Regex("""\b(?:5[1-5][0-9]{14}|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[01][0-9]|720)[0-9]{12})\b""")),
        PatternEntry("credit_card_amex", Regex("""\b3[47][0-9]{13}\b""")),
        PatternEntry("iban", Regex("""\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b"""))
    )

    val PII: List<PatternEntry> = listOf(
        PatternEntry("ssn", Regex("""\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b""")),
        PatternEntry("email", Regex("""\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b""")),
        PatternEntry("us_phone", Regex("""\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"""))
    )

    private val CATEGORY_MAP: Map<SensitiveDataCategory, List<PatternEntry>> = mapOf(
        SensitiveDataCategory.FINANCIAL to FINANCIAL,
        SensitiveDataCategory.CREDENTIALS to CredentialPatterns.ALL,
        SensitiveDataCategory.PII to PII
    )

    val ALL: List<PatternEntry> = CATEGORY_MAP.values.flatten()

    fun patternsForCategories(categories: List<String>? = null): List<PatternEntry> {
        if (categories.isNullOrEmpty()) return ALL
        val filtered = CATEGORY_MAP.filterKeys { it.label() in categories }
        return filtered.values.flatten()
    }

    fun matchesByCategory(content: String, categories: List<String>? = null): Map<String, List<String>> {
        val entries = if (categories.isNullOrEmpty()) CATEGORY_MAP
            else CATEGORY_MAP.filterKeys { it.label() in categories }
        return entries.flatMap { (category, patterns) ->
            patterns.filter { it.regex.containsMatchIn(content) }
                .map { category.label() to it.name }
        }.groupBy({ it.first }, { it.second })
    }
}
