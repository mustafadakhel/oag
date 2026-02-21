package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.PolicyRequest
import java.util.Locale

internal fun scopeMatchesRequest(
    hosts: List<String>?,
    methods: List<String>?,
    paths: List<String>?,
    ipRanges: List<String>?,
    request: PolicyRequest
): Boolean {
    if (!matchesHostList(hosts, request.host)) return false
    if (!matchesMethod(methods, request.method)) return false
    if (!matchesPath(paths, request.path)) return false
    if (!matchesIpRange(ipRanges, request.host)) return false
    return true
}

private fun matchesHostList(hosts: List<String>?, host: String): Boolean {
    if (hosts.isNullOrEmpty()) return true
    return hosts.any { matchesHost(it, host) }
}

internal fun normalizeHosts(hosts: List<String>?): List<String>? =
    hosts?.mapNotNull { it.trim().trimEnd('.').lowercase(Locale.ROOT).ifEmpty { null } }

internal fun normalizeMethods(methods: List<String>?): List<String>? =
    methods?.mapNotNull { it.trim().uppercase(Locale.ROOT).ifEmpty { null } }

internal fun normalizePaths(paths: List<String>?): List<String>? =
    paths?.mapNotNull { it.trim().ifEmpty { null } }

internal fun normalizeIpRanges(ipRanges: List<String>?): List<String>? =
    ipRanges?.mapNotNull { it.trim().ifEmpty { null } }
