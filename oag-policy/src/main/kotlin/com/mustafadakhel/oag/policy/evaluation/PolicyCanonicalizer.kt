package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAnchoredPattern
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyHeaderMatch
import com.mustafadakhel.oag.policy.core.PolicyHeaderRewrite
import com.mustafadakhel.oag.policy.core.PolicyPayloadMatch
import com.mustafadakhel.oag.policy.core.PolicyQueryMatch
import com.mustafadakhel.oag.policy.core.PolicyResponseRewrite
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.SecretScope
import com.mustafadakhel.oag.policy.evaluation.dimension.matchDimensions

import java.util.Locale

fun canonicalizePolicy(policy: PolicyDocument): PolicyDocument {
    val normalized = policy.normalize()
    val canonicalDefaults = normalized.defaults?.let { d ->
        d.copy(
            dataClassification = d.dataClassification?.let {
                it.copy(
                    customPatterns = it.customPatterns?.sorted(),
                    categories = it.categories?.sorted()
                )
            }
        )
    }
    return PolicyDocument(
        version = normalized.version,
        defaults = canonicalDefaults,
        allow = normalized.allow?.map { canonicalizeRule(it) }?.sortedWith(ruleComparator()),
        deny = normalized.deny?.map { canonicalizeRule(it) }?.sortedWith(ruleComparator()),
        secretScopes = normalized.secretScopes?.map { canonicalizeSecretScope(it) }?.sortedWith(secretScopeComparator()),
        agentProfiles = normalized.agentProfiles?.sortedBy { it.id }?.map { profile ->
            profile.copy(
                allowedRules = profile.allowedRules?.sorted(),
                deniedRules = profile.deniedRules?.sorted(),
                tags = profile.tags?.sorted()
            )
        }
    )
}

private fun canonicalizeRule(rule: PolicyRule): PolicyRule {
    // Canonicalize dimension-owned fields via the protocol
    val dimensionCanonicalized = matchDimensions.fold(rule) { r, dim -> dim.canonicalize(r) }
    // Canonicalize non-dimension fields that have no corresponding MatchDimension
    return dimensionCanonicalized.copy(
        secrets = dimensionCanonicalized.secrets?.sorted(),
        tags = dimensionCanonicalized.tags?.sorted(),
        contentInspection = dimensionCanonicalized.contentInspection?.let {
            it.copy(
                customPatterns = it.customPatterns?.sorted(),
                anchoredPatterns = it.anchoredPatterns?.sortedWith(
                    compareBy<PolicyAnchoredPattern> { ap -> ap.pattern }
                        .thenBy { ap -> ap.anchor?.label().orEmpty() }
                )
            )
        },
        headerRewrites = dimensionCanonicalized.headerRewrites?.sortedWith(
            compareBy<PolicyHeaderRewrite> { it.header.lowercase(Locale.ROOT) }
                .thenBy { it.action.label() }
                .thenBy { it.value.orEmpty() }
        ),
        dataClassification = dimensionCanonicalized.dataClassification?.let {
            it.copy(
                customPatterns = it.customPatterns?.sorted(),
                categories = it.categories?.sorted()
            )
        },
        responseRewrites = dimensionCanonicalized.responseRewrites?.sortedWith(
            compareBy<PolicyResponseRewrite> { it.action.name }
                .thenBy { it.canonicalSortKey() }
        ),
        webhookEvents = dimensionCanonicalized.webhookEvents?.sorted()
    )
}

private fun canonicalizeSecretScope(scope: SecretScope): SecretScope =
    scope.copy(
        hosts = scope.hosts?.sorted(),
        methods = scope.methods?.sorted(),
        paths = scope.paths?.sorted(),
        ipRanges = scope.ipRanges?.sorted()
    )

private fun ruleComparator(): Comparator<PolicyRule> {
    return compareBy<PolicyRule> { it.id.orEmpty() }
        .thenBy { it.host.orEmpty() }
        .thenBy { it.methods.canonicalKey() }
        .thenBy { it.paths.canonicalKey() }
        .thenBy { it.secrets.canonicalKey() }
        .thenBy { it.ipRanges.canonicalKey() }
        .thenBy { it.maxBodyBytes ?: -1L }
}

private fun secretScopeComparator(): Comparator<SecretScope> {
    return compareBy<SecretScope> { it.id.orEmpty() }
        .thenBy { it.hosts.canonicalKey() }
        .thenBy { it.methods.canonicalKey() }
        .thenBy { it.paths.canonicalKey() }
        .thenBy { it.ipRanges.canonicalKey() }
}

private fun PolicyResponseRewrite.canonicalSortKey(): String = when (this) {
    is PolicyResponseRewrite.Redact -> pattern
    is PolicyResponseRewrite.RemoveHeader -> header
    is PolicyResponseRewrite.SetHeader -> "$header|$value"
}

private fun List<String>?.canonicalKey(): String =
    this?.sorted()?.joinToString("|").orEmpty()
