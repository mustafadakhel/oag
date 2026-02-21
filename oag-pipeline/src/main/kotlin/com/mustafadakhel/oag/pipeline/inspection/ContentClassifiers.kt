package com.mustafadakhel.oag.pipeline.inspection
import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.inspection.content.CredentialPatterns
import com.mustafadakhel.oag.inspection.content.SensitiveDataPatterns
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDataClassification
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.cachedRegex

fun checkOutboundCredentials(body: String): List<String> =
    CredentialPatterns.matches(body)

fun checkDataClassification(
    body: String,
    config: PolicyDataClassification,
    onError: (String) -> Unit = defaultInspectionErrorHandler
): DataClassificationResult {
    val byCategory = if (config.enableBuiltinPatterns == true) {
        SensitiveDataPatterns.matchesByCategory(body, config.categories)
    } else {
        emptyMap()
    }

    val allMatches = buildList {
        for ((_, matches) in byCategory) addAll(matches)
        if (!config.customPatterns.isNullOrEmpty()) {
            for (pattern in config.customPatterns) {
                val hit = runCatching { cachedRegex(pattern).containsMatchIn(body) }
                    .onFailure { e -> onError("credential scan regex failed pattern=$pattern: ${e.message}") }
                    .getOrDefault(true)
                if (hit) add("custom:$pattern")
            }
        }
    }

    val allCategories = byCategory.keys.toList()

    val decision = allMatches.takeIf { it.isNotEmpty() }?.let {
        PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.SENSITIVE_DATA_DETECTED)
    }

    return DataClassificationResult(decision, allMatches, allCategories)
}
