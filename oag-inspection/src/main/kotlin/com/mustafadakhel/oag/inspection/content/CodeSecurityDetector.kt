package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.inspection.Detector
import com.mustafadakhel.oag.inspection.EvidenceKey
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.ResponseTextBody

private const val DEFAULT_CONFIDENCE = 0.80
private const val DEFAULT_TIME_BUDGET_NANOS = 50_000_000L
private const val REGEX_SAFETY_INPUT_SIZE = 10_000
private const val REGEX_SAFETY_MAX_MS = 5L
private const val YAML_UNSAFE_RULE_ID = "deser_yaml_unsafe"

class CodeSecurityDetector(
    private val rules: List<CodeSecurityRule> = CodeSecurityRules.ALL,
    private val timeBudgetNanos: Long = DEFAULT_TIME_BUDGET_NANOS
) : Detector<ResponseTextBody> {

    init {
        validateRegexSafety(rules)
    }

    override fun inspect(input: ResponseTextBody, ctx: InspectionContext): List<Finding> {
        val blocks = CodeBlockExtractor.extract(input.text)
        if (blocks.isEmpty()) return emptyList()

        val startNanos = System.nanoTime()
        return buildList {
            for (block in blocks) {
                for (rule in rules) {
                    if (System.nanoTime() - startNanos > timeBudgetNanos) return@buildList
                    if (matchesRule(rule, block.code)) {
                        add(rule.toFinding(block))
                    }
                }
            }
        }
    }
}

private fun matchesRule(rule: CodeSecurityRule, code: String): Boolean {
    val matches = try {
        rule.regex.containsMatchIn(code)
    } catch (_: StackOverflowError) {
        return false
    }
    if (!matches) return false
    if (rule.id != YAML_UNSAFE_RULE_ID) return true
    return !yamlLoadIsSafe(code, rule.regex)
}

private fun yamlLoadIsSafe(code: String, regex: Regex): Boolean =
    regex.findAll(code).all { match ->
        val line = code.lineContaining(match.range.first)
        "SafeLoader" in line || "safe_load" in line
    }

private fun String.lineContaining(index: Int): String {
    val start = lastIndexOf('\n', index - 1) + 1
    val end = indexOf('\n', index).let { if (it == -1) length else it }
    return substring(start, end)
}

private fun CodeSecurityRule.toFinding(block: ExtractedCodeBlock) = Finding(
    type = FindingType.CODE_VULNERABILITY,
    severity = severity,
    confidence = DEFAULT_CONFIDENCE,
    location = FindingLocation.ResponseBody,
    evidence = buildMap {
        put(EvidenceKey.PATTERN, id)
        put(EvidenceKey.CWE, cwe)
        put(EvidenceKey.CODE_BLOCK_SOURCE, block.source.label())
        if (block.language != null) put(EvidenceKey.LANGUAGE, block.language)
    },
    recommendedActions = listOf(recommendedAction)
)

private fun validateRegexSafety(rules: List<CodeSecurityRule>) {
    val adversarial = "a".repeat(REGEX_SAFETY_INPUT_SIZE)
    val maxNanos = REGEX_SAFETY_MAX_MS * 1_000_000L
    rules.forEach { rule ->
        val startNanos = System.nanoTime()
        rule.regex.containsMatchIn(adversarial)
        val elapsedNanos = System.nanoTime() - startNanos
        require(elapsedNanos < maxNanos) {
            "Regex for rule '${rule.id}' took ${elapsedNanos / 1_000_000}ms on adversarial input (limit: ${REGEX_SAFETY_MAX_MS}ms)"
        }
    }
}
