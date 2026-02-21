package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.cachedRegex
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.normalizeContent
import com.mustafadakhel.oag.policy.core.DetectedProtocol
import com.mustafadakhel.oag.policy.core.StructuredPayload
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyCondition
import com.mustafadakhel.oag.policy.core.PolicyHeaderMatch
import com.mustafadakhel.oag.policy.core.PolicyPayloadMatch
import com.mustafadakhel.oag.policy.core.PolicyQueryMatch
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.support.contains
import com.mustafadakhel.oag.policy.support.parseIpRange

import java.util.Locale

private val defaultRegexFailureHandler: (String) -> Unit = { msg -> System.err.println("${LOG_PREFIX}$msg") }

private fun warnRegexFailure(context: String, e: Throwable, onError: (String) -> Unit = defaultRegexFailureHandler) {
    onError("$context: ${e.message}")
}

internal fun matchesHost(ruleHost: String?, requestHost: String): Boolean {
    if (ruleHost.isNullOrBlank()) return false
    // Defensive normalization — rule hosts are pre-normalized at load time via
    // HostDimension.normalize(), but request hosts need runtime normalization.
    val normalizedRule = ruleHost.trim().trimEnd('.').lowercase(Locale.ROOT)
    val normalizedHost = requestHost.trim().trimEnd('.').lowercase(Locale.ROOT)
    return if (normalizedRule.startsWith("*.") && normalizedRule.length > 2) {
        val suffix = normalizedRule.removePrefix("*.")
        normalizedHost != suffix && normalizedHost.endsWith(".$suffix")
    } else {
        normalizedHost == normalizedRule
    }
}

internal fun matchesMethod(ruleMethods: List<String>?, method: String): Boolean {
    if (ruleMethods.isNullOrEmpty()) return true
    return ruleMethods.any { it.equals(method, ignoreCase = true) }
}

internal fun matchesPath(rulePaths: List<String>?, path: String): Boolean {
    if (rulePaths.isNullOrEmpty()) return true
    val normalizedPath = path.trim()
    return rulePaths.any { it.trim().globMatches(normalizedPath) }
}

/**
 * Matches [host] against CIDR ranges in [ruleRanges]. The [host] parameter is the
 * request target host, which may be either a hostname (e.g. "api.example.com") or an
 * IP literal (e.g. "10.0.0.1", "::1"). Only IP literals are matchable against CIDR
 * ranges; hostnames yield no match (returns false) because DNS resolution at evaluation
 * time would be unreliable and introduce a TOCTOU gap with the actual connection.
 */
internal fun matchesIpRange(ruleRanges: List<String>?, host: String): Boolean {
    if (ruleRanges.isNullOrEmpty()) return true
    val address = host.toIpLiteralOrNull() ?: return false
    return ruleRanges.any { range -> parseIpRange(range).contains(address) }
}

internal fun matchesConditions(conditions: PolicyCondition?, request: PolicyRequest): Boolean {
    if (conditions == null) return true
    if (conditions.scheme != null && !conditions.scheme.equals(request.scheme, ignoreCase = true)) return false
    if (!conditions.ports.isNullOrEmpty() && request.port !in conditions.ports) return false
    return true
}

fun matchesBody(bodyMatch: PolicyBodyMatch?, body: String?, onRegexError: (String) -> Unit = defaultRegexFailureHandler): Boolean {
    if (bodyMatch == null) return true
    if (body == null) return false

    val normalized = body.normalizeContent()

    val containsMatch = bodyMatch.contains.isNullOrEmpty() ||
        bodyMatch.contains.all { literal -> normalized.contains(literal.normalizeContent()) }

    val patternMatch = bodyMatch.patterns.isNullOrEmpty() ||
        bodyMatch.patterns.all { pattern ->
            runCatching { cachedRegex(pattern).containsMatchIn(normalized) }
                .onFailure { e -> warnRegexFailure("body match regex failed pattern=$pattern", e, onRegexError) }
                .getOrDefault(false)
        }

    return containsMatch && patternMatch
}

internal fun matchesHeaders(headerMatch: List<PolicyHeaderMatch>?, headers: Map<String, String>, onRegexError: (String) -> Unit = defaultRegexFailureHandler): Boolean {
    if (headerMatch.isNullOrEmpty()) return true
    return headerMatch.all { match ->
        val headerValue = headers.entries.firstOrNull { it.key.equals(match.header, ignoreCase = true) }?.value
        when {
            match.present != null -> if (match.present) headerValue != null else headerValue == null
            match.value != null -> headerValue != null && headerValue.equals(match.value, ignoreCase = true)
            match.pattern != null -> headerValue != null && (runCatching { cachedRegex(match.pattern) }
                .onFailure { e -> warnRegexFailure("header match regex failed pattern=${match.pattern}", e, onRegexError) }
                .getOrNull()?.containsMatchIn(headerValue) == true)
            else -> true
        }
    }
}

internal fun matchesQueryParams(queryMatch: List<PolicyQueryMatch>?, path: String, onRegexError: (String) -> Unit = defaultRegexFailureHandler): Boolean {
    if (queryMatch.isNullOrEmpty()) return true
    val parsed = parseQueryParams(path)
    // Invalid percent-encoding causes a no-match (returns false). This is a fallback
    // safety net; the primary mitigation is blockInvalidPercentEncoding in
    // PolicyUrlInspection, which rejects malformed requests at the pipeline level.
    if (parsed.hasInvalidEncoding) return false
    val params = parsed.params
    return queryMatch.all { match ->
        val values = params[match.param]
        when {
            match.present != null -> if (match.present) values != null else values == null
            match.value != null -> values != null && values.any { it.equals(match.value, ignoreCase = true) }
            match.pattern != null -> values != null && values.any {
                runCatching { cachedRegex(match.pattern) }
                    .onFailure { e -> warnRegexFailure("query match regex failed pattern=${match.pattern}", e, onRegexError) }
                    .getOrNull()?.containsMatchIn(it) == true
            }
            else -> true
        }
    }
}

internal fun matchesPayload(payloadMatch: List<PolicyPayloadMatch>?, payload: StructuredPayload?, onRegexError: (String) -> Unit = defaultRegexFailureHandler): Boolean {
    if (payloadMatch.isNullOrEmpty()) return true
    if (payload == null) return false
    return payloadMatch.any { match ->
        val expected = DetectedProtocol.fromProtocolId(match.protocol) ?: return@any false
        if (payload.protocol != expected) return@any false
        if (!matchesRegexField(match.method, payload.method, "method", onRegexError)) return@any false
        if (!matchesRegexField(match.operation, payload.operationName, "operation", onRegexError)) return@any false
        if (match.operationType != null) {
            val typeLabel = payload.operationType?.label()
            if (typeLabel == null || !match.operationType.equals(typeLabel, ignoreCase = true)) return@any false
        }
        true
    }
}

private fun matchesRegexField(spec: String?, actual: String?, fieldName: String, onRegexError: (String) -> Unit = defaultRegexFailureHandler): Boolean {
    if (spec == null) return true
    if (actual == null) return false
    val regex = runCatching { cachedRegex(spec) }
        .onFailure { e -> warnRegexFailure("payload match regex failed $fieldName=$spec", e, onRegexError) }
        .getOrNull() ?: return false
    return regex.containsMatchIn(actual)
}

/** Glob match where `*` matches any characters including `/` (cross-segment). */
internal fun String.globMatches(value: String): Boolean {
    if (this == "*") return true
    var patternIndex = 0
    var valueIndex = 0
    var lastStarIndex = -1
    var matchAfterStar = 0

    while (valueIndex < value.length) {
        when {
            patternIndex < length && this[patternIndex] == value[valueIndex] -> {
                patternIndex += 1
                valueIndex += 1
            }
            patternIndex < length && this[patternIndex] == '*' -> {
                lastStarIndex = patternIndex
                patternIndex += 1
                matchAfterStar = valueIndex
            }
            lastStarIndex != -1 -> {
                patternIndex = lastStarIndex + 1
                matchAfterStar += 1
                valueIndex = matchAfterStar
            }
            else -> return false
        }
    }

    while (patternIndex < length && this[patternIndex] == '*') {
        patternIndex += 1
    }

    return patternIndex == length
}
