package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyResponseRewrite
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.isRegexSafe

import java.util.Locale

enum class LintCode {
SHADOWED_RULE,
OVERLAPPING_RULES,
UNUSED_SECRET_REF,
UNREACHABLE_ALLOW,
UNSAFE_REGEX,
UNSAFE_DEFAULT_ALLOW
}

data class LintWarning(
val code: LintCode,
val message: String,
val ruleId: String? = null,
val ruleIndex: Int? = null,
val section: String? = null
)



fun lintPolicy(document: PolicyDocument): List<LintWarning> =
    checkUnsafeDefaultAllow(document) +
        checkShadowedRules(document) +
        checkOverlappingRules(document) +
        checkUnusedSecrets(document) +
        checkUnreachableAllowRules(document) +
        checkUnsafeRegex(document)

internal fun checkUnsafeDefaultAllow(document: PolicyDocument): List<LintWarning> =
    if (document.defaults?.action == PolicyAction.ALLOW) {
        listOf(LintWarning(
            code = LintCode.UNSAFE_DEFAULT_ALLOW,
            message = "defaults.action is 'allow' — requests not matched by any deny rule will be forwarded, disabling default-deny security posture"
        ))
    } else emptyList()

internal fun checkShadowedRules(document: PolicyDocument): List<LintWarning> =
    checkShadowedInSection(document.allow, PolicyAction.ALLOW.label()) +
        checkShadowedInSection(document.deny, PolicyAction.DENY.label())

private fun checkShadowedInSection(rules: List<PolicyRule>?, section: String): List<LintWarning> {
    if (rules.isNullOrEmpty()) return emptyList()
    // Index earlier rules by host pattern for O(1) candidate lookup instead of O(n) scan.
    val byExactHost = mutableMapOf<String, MutableList<IndexedValue<PolicyRule>>>()
    val byWildcardSuffix = mutableMapOf<String, MutableList<IndexedValue<PolicyRule>>>()
    return buildList {
        for ((index, rule) in rules.withIndex()) {
            val shadower = shadowCandidatesFor(rule.host, byExactHost, byWildcardSuffix)
                .firstOrNull { ruleShadows(it.value, rule) }
            if (shadower != null) {
                val earlierId = shadower.value.id ?: "index ${shadower.index}"
                val laterId = rule.id ?: "index $index"
                add(LintWarning(
                    code = LintCode.SHADOWED_RULE,
                    message = "$section rule '$laterId' is shadowed by earlier rule '$earlierId'",
                    ruleId = rule.id,
                    ruleIndex = index,
                    section = section
                ))
            }
            indexRuleByHost(IndexedValue(index, rule), byExactHost, byWildcardSuffix)
        }
    }
}

private fun shadowCandidatesFor(
    laterHost: String?,
    byExactHost: Map<String, List<IndexedValue<PolicyRule>>>,
    byWildcardSuffix: Map<String, List<IndexedValue<PolicyRule>>>
): Sequence<IndexedValue<PolicyRule>> {
    val host = laterHost?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT)
        ?: return emptySequence()
    return sequence {
        if (host.startsWith("*.") && host.length > 2) {
            val suffix = host.removePrefix("*.")
            byWildcardSuffix[suffix]?.let { yieldAll(it) }
            suffixesOf(suffix).forEach { parent ->
                byWildcardSuffix[parent]?.let { yieldAll(it) }
            }
        } else {
            byExactHost[host]?.let { yieldAll(it) }
            suffixesOf(host).forEach { suffix ->
                byWildcardSuffix[suffix]?.let { yieldAll(it) }
            }
        }
    }
}

private fun indexRuleByHost(
    indexed: IndexedValue<PolicyRule>,
    byExactHost: MutableMap<String, MutableList<IndexedValue<PolicyRule>>>,
    byWildcardSuffix: MutableMap<String, MutableList<IndexedValue<PolicyRule>>>
) {
    val host = indexed.value.host?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT) ?: return
    if (host.startsWith("*.") && host.length > 2) {
        byWildcardSuffix.getOrPut(host.removePrefix("*.")) { mutableListOf() }.add(indexed)
    } else {
        byExactHost.getOrPut(host) { mutableListOf() }.add(indexed)
    }
}

private fun indexExactHostBySuffix(
    indexed: IndexedValue<PolicyRule>,
    bySuffix: MutableMap<String, MutableList<IndexedValue<PolicyRule>>>
) {
    val host = indexed.value.host?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT) ?: return
    if (host.startsWith("*.")) return
    bySuffix.getOrPut(host) { mutableListOf() }.add(indexed)
    for (suffix in suffixesOf(host)) {
        bySuffix.getOrPut(suffix) { mutableListOf() }.add(indexed)
    }
}

private fun overlapCandidatesFor(
    host: String?,
    byExactHost: Map<String, List<IndexedValue<PolicyRule>>>,
    byWildcardSuffix: Map<String, List<IndexedValue<PolicyRule>>>,
    exactBySuffix: Map<String, List<IndexedValue<PolicyRule>>>
): Sequence<IndexedValue<PolicyRule>> {
    val normalizedHost = host?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT) ?: return emptySequence()
    return sequence {
        if (normalizedHost.startsWith("*.") && normalizedHost.length > 2) {
            val suffix = normalizedHost.removePrefix("*.")
            // Wildcard-to-wildcard: same or parent suffixes
            byWildcardSuffix[suffix]?.let { yieldAll(it) }
            for (parent in suffixesOf(suffix)) {
                byWildcardSuffix[parent]?.let { yieldAll(it) }
            }
            // Wildcard-to-wildcard: child suffixes
            for ((wSuffix, rules) in byWildcardSuffix) {
                if (wSuffix != suffix && wSuffix.endsWith(".$suffix")) yieldAll(rules)
            }
            // Wildcard-to-exact: any exact host under this wildcard domain
            exactBySuffix[suffix]?.let { yieldAll(it) }
        } else {
            // Exact-to-exact: same host
            byExactHost[normalizedHost]?.let { yieldAll(it) }
            // Exact-to-wildcard: wildcards that cover this host
            for (suffix in suffixesOf(normalizedHost)) {
                byWildcardSuffix[suffix]?.let { yieldAll(it) }
            }
        }
    }
}

private fun suffixesOf(host: String): List<String> {
    val parts = host.split('.')
    return (1 until parts.size).map { parts.drop(it).joinToString(".") }
}

/**
 * Returns true if [earlier] shadows [later] — i.e., every request that matches
 * [later] would also match [earlier], making [later] unreachable.
 */
internal fun ruleShadows(earlier: PolicyRule, later: PolicyRule): Boolean {
    if (!earlier.ipRanges.isNullOrEmpty()) return false
    if (earlier.conditions != null) return false
    if (earlier.bodyMatch != null) return false
    if (!earlier.headerMatch.isNullOrEmpty()) return false
    if (!earlier.queryMatch.isNullOrEmpty()) return false
    if (!earlier.payloadMatch.isNullOrEmpty()) return false

    if (!hostCovers(earlier.host, later.host)) return false
    if (!methodsCovers(earlier.methods, later.methods)) return false
    if (!pathsCovers(earlier.paths, later.paths)) return false
    return true
}

internal fun checkOverlappingRules(document: PolicyDocument): List<LintWarning> {
    val allowRules = document.allow.orEmpty()
    val denyRules = document.deny.orEmpty()
    if (allowRules.isEmpty() || denyRules.isEmpty()) return emptyList()

    val denyByExactHost = mutableMapOf<String, MutableList<IndexedValue<PolicyRule>>>()
    val denyByWildcardSuffix = mutableMapOf<String, MutableList<IndexedValue<PolicyRule>>>()
    val denyExactBySuffix = mutableMapOf<String, MutableList<IndexedValue<PolicyRule>>>()
    for ((index, rule) in denyRules.withIndex()) {
        val iv = IndexedValue(index, rule)
        indexRuleByHost(iv, denyByExactHost, denyByWildcardSuffix)
        indexExactHostBySuffix(iv, denyExactBySuffix)
    }

    return buildList {
        for ((ai, allowRule) in allowRules.withIndex()) {
            val candidates = overlapCandidatesFor(
                allowRule.host, denyByExactHost, denyByWildcardSuffix, denyExactBySuffix
            )
            for (candidate in candidates) {
                val denyRule = candidate.value
                val overlaps = methodsOverlap(allowRule.methods, denyRule.methods) &&
                    pathsOverlap(allowRule.paths, denyRule.paths)
                if (overlaps) {
                    val allowId = allowRule.id ?: "allow index $ai"
                    val denyId = denyRule.id ?: "deny index ${candidate.index}"
                    add(LintWarning(
                        code = LintCode.OVERLAPPING_RULES,
                        message = "allow rule '$allowId' and deny rule '$denyId' overlap in scope (deny takes precedence)",
                        ruleId = allowRule.id,
                        ruleIndex = ai,
                        section = PolicyAction.ALLOW.label()
                    ))
                }
            }
        }
    }
}


internal fun checkUnusedSecrets(document: PolicyDocument): List<LintWarning> {
    val definedIds = document.secretScopes?.mapNotNull { it.id }?.toSet() ?: emptySet()
    return buildList {
        val sections = listOf(
            PolicyAction.ALLOW.label() to document.allow,
            PolicyAction.DENY.label() to document.deny
        )
        for ((section, rules) in sections) {
            rules?.forEachIndexed { index, rule ->
                rule.secrets?.forEach { secretId ->
                    if (secretId !in definedIds) {
                        val ruleLabel = rule.id ?: "index $index"
                        add(LintWarning(
                            code = LintCode.UNUSED_SECRET_REF,
                            message = "$section rule '$ruleLabel' references secret '$secretId' not defined in secret_scopes",
                            ruleId = rule.id,
                            ruleIndex = index,
                            section = section
                        ))
                    }
                }
            }
        }
    }
}

internal fun checkUnreachableAllowRules(document: PolicyDocument): List<LintWarning> {
    val allowRules = document.allow.orEmpty()
    val denyRules = document.deny.orEmpty()
    if (allowRules.isEmpty() || denyRules.isEmpty()) return emptyList()
    return buildList {
        for ((ai, allowRule) in allowRules.withIndex()) {
            val shadowingDeny = denyRules.firstOrNull { denyRule -> denyShadowsAllow(denyRule, allowRule) }
            if (shadowingDeny != null) {
                val allowId = allowRule.id ?: "allow index $ai"
                val denyId = shadowingDeny.id ?: "deny rule"
                add(LintWarning(
                    code = LintCode.UNREACHABLE_ALLOW,
                    message = "allow rule '$allowId' is unreachable, deny rule '$denyId' matches all its traffic",
                    ruleId = allowRule.id,
                    ruleIndex = ai,
                    section = PolicyAction.ALLOW.label()
                ))
            }
        }
    }
}

/**
 * Returns true if [denyRule] covers all traffic that [allowRule] would match,
 * meaning deny always takes precedence and the allow rule is unreachable.
 */
private fun denyShadowsAllow(denyRule: PolicyRule, allowRule: PolicyRule): Boolean =
    ruleShadows(denyRule, allowRule)

internal fun checkUnsafeRegex(document: PolicyDocument): List<LintWarning> = buildList {
    fun addIfUnsafe(pattern: String, label: String, section: String, ruleId: String? = null, ruleIndex: Int? = null) {
        if (!isRegexSafe(pattern)) {
            add(LintWarning(
                code = LintCode.UNSAFE_REGEX,
                message = "$section $label has unsafe regex pattern: $pattern",
                ruleId = ruleId,
                ruleIndex = ruleIndex,
                section = section
            ))
        }
    }

    for ((section, rules) in listOf(PolicyAction.ALLOW.label() to document.allow, PolicyAction.DENY.label() to document.deny)) {
        rules?.forEachIndexed { index, rule ->
            val ruleLabel = "rule '${rule.id ?: "index $index"}'"
            rule.bodyMatch?.patterns?.forEach { addIfUnsafe(it, ruleLabel, section, rule.id, index) }
            rule.headerMatch?.forEach { it.pattern?.let { p -> addIfUnsafe(p, ruleLabel, section, rule.id, index) } }
            rule.queryMatch?.forEach { it.pattern?.let { p -> addIfUnsafe(p, ruleLabel, section, rule.id, index) } }
            rule.payloadMatch?.forEach { pm ->
                pm.method?.let { addIfUnsafe(it, ruleLabel, section, rule.id, index) }
                pm.operation?.let { addIfUnsafe(it, ruleLabel, section, rule.id, index) }
            }
            rule.contentInspection?.customPatterns?.forEach { addIfUnsafe(it, ruleLabel, section, rule.id, index) }
            rule.contentInspection?.anchoredPatterns?.forEach {
                addIfUnsafe(it.pattern, ruleLabel, section, rule.id, index)
            }
            rule.responseRewrites?.filterIsInstance<PolicyResponseRewrite.Redact>()?.forEach {
                addIfUnsafe(it.pattern, ruleLabel, section, rule.id, index)
            }
            rule.dataClassification?.customPatterns?.forEach { addIfUnsafe(it, ruleLabel, section, rule.id, index) }
        }
}
document.defaults?.dataClassification?.customPatterns?.forEach { addIfUnsafe(it, "defaults", "defaults") }
document.defaults?.contentInspection?.customPatterns?.forEach { addIfUnsafe(it, "defaults", "defaults") }
document.defaults?.contentInspection?.anchoredPatterns?.forEach { addIfUnsafe(it.pattern, "defaults", "defaults") }
}

/**
 * Returns true if [coverHost] matches at least everything that [coveredHost] matches.
 * A null/blank host matches nothing, so it cannot cover or be covered.
 */
internal fun hostCovers(coverHost: String?, coveredHost: String?): Boolean {
    if (coverHost.isNullOrBlank() || coveredHost.isNullOrBlank()) return false
    val cover = coverHost.trim().trimEnd('.').lowercase(Locale.ROOT)
    val covered = coveredHost.trim().trimEnd('.').lowercase(Locale.ROOT)
    if (cover == covered) return true
    if (cover.startsWith("*.") && cover.length > 2) {
        val suffix = cover.removePrefix("*.")
        if (covered.startsWith("*.") && covered.length > 2) {
            val coveredSuffix = covered.removePrefix("*.")
            return coveredSuffix.endsWith(".$suffix") || coveredSuffix == suffix
        }
        return covered.endsWith(".$suffix")
    }
    return false
}

/**
 * Returns true if [coverMethods] matches at least everything that [coveredMethods] matches.
 * Null/empty means "all methods".
 */
internal fun methodsCovers(coverMethods: List<String>?, coveredMethods: List<String>?): Boolean {
    if (coverMethods.isNullOrEmpty()) return true
    if (coveredMethods.isNullOrEmpty()) return false
    val coverSet = coverMethods.map { it.trim().uppercase(Locale.ROOT) }.toSet()
    val coveredSet = coveredMethods.map { it.trim().uppercase(Locale.ROOT) }.toSet()
    return coverSet.containsAll(coveredSet)
}

/**
 * Returns true if [coverPaths] matches at least everything that [coveredPaths] matches.
 * Null/empty means "all paths".
 */
internal fun pathsCovers(coverPaths: List<String>?, coveredPaths: List<String>?): Boolean {
    if (coverPaths.isNullOrEmpty()) return true
    if (coveredPaths.isNullOrEmpty()) return false
    return coveredPaths.all { coveredPath ->
        coverPaths.any { coverGlob -> globCovers(coverGlob.trim(), coveredPath.trim()) }
    }
}

/**
 * Returns true if [coverGlob] matches at least everything that [coveredGlob] matches.
 * Uses conservative heuristics: exact match, prefix wildcard coverage, and catch-all.
 */
internal fun globCovers(coverGlob: String, coveredGlob: String): Boolean {
    if (coverGlob == "*") return true
    if (coverGlob == coveredGlob) return true
    if (coverGlob.endsWith("*")) {
        val prefix = coverGlob.dropLast(1)
        if (coveredGlob.startsWith(prefix)) return true
    }
    return false
}

/**
 * Returns true if [hostA] and [hostB] could match the same hostname.
 */
internal fun hostsOverlap(hostA: String?, hostB: String?): Boolean {
    if (hostA.isNullOrBlank() || hostB.isNullOrBlank()) return false
    val normalizedA = hostA.trim().trimEnd('.').lowercase(Locale.ROOT)
    val normalizedB = hostB.trim().trimEnd('.').lowercase(Locale.ROOT)
    if (normalizedA == normalizedB) return true
    if (normalizedA.startsWith("*.") && normalizedA.length > 2) {
        val suffix = normalizedA.removePrefix("*.")
        if (normalizedB.startsWith("*.") && normalizedB.length > 2) {
            val bSuffix = normalizedB.removePrefix("*.")
            return bSuffix.endsWith(".$suffix") || bSuffix == suffix ||
                suffix.endsWith(".$bSuffix") || suffix == bSuffix
        }
        return normalizedB.endsWith(".$suffix") || normalizedB == suffix
    }
    if (normalizedB.startsWith("*.") && normalizedB.length > 2) {
        val suffix = normalizedB.removePrefix("*.")
        return normalizedA.endsWith(".$suffix") || normalizedA == suffix
    }
    return false
}

/**
 * Returns true if [methodsA] and [methodsB] could match the same HTTP method.
 */
internal fun methodsOverlap(methodsA: List<String>?, methodsB: List<String>?): Boolean {
    if (methodsA.isNullOrEmpty() || methodsB.isNullOrEmpty()) return true
    val setA = methodsA.map { it.trim().uppercase(Locale.ROOT) }.toSet()
    val setB = methodsB.map { it.trim().uppercase(Locale.ROOT) }.toSet()
    return setA.intersect(setB).isNotEmpty()
}

/**
 * Returns true if [pathsA] and [pathsB] could match the same path.
 */
internal fun pathsOverlap(pathsA: List<String>?, pathsB: List<String>?): Boolean {
    if (pathsA.isNullOrEmpty() || pathsB.isNullOrEmpty()) return true
    return pathsA.any { pa ->
        pathsB.any { pb -> globsOverlap(pa.trim(), pb.trim()) }
    }
}

/**
 * Returns true if two globs could match the same string.
 */
internal fun globsOverlap(globA: String, globB: String): Boolean {
    if (globA == "*" || globB == "*") return true
    if (globA == globB) return true
    // If either has a wildcard suffix, check prefix overlap
    if (globA.endsWith("*") && globB.endsWith("*")) {
        val prefixA = globA.dropLast(1)
        val prefixB = globB.dropLast(1)
        return prefixA.startsWith(prefixB) || prefixB.startsWith(prefixA)
    }
    if (globA.endsWith("*")) {
        return globB.startsWith(globA.dropLast(1))
    }
    if (globB.endsWith("*")) {
        return globA.startsWith(globB.dropLast(1))
    }
    return false
}
