package com.mustafadakhel.oag.policy.evaluation

import java.net.InetAddress

internal fun String.toIpLiteralOrNull(): InetAddress? {
    if (!isIpLiteralHost()) return null
    return runCatching { InetAddress.getByName(this) }.getOrNull()
}

internal fun String.isIpLiteralHost(): Boolean =
    isIpv4Literal() || isIpv6Literal()

private const val IPV4_OCTET_COUNT = 4
private const val IPV6_HEX_GROUPS_WITH_IPV4 = 6
private const val IPV6_HEX_GROUP_COUNT = 8
private const val MAX_IPV6_HEX_GROUP_LENGTH = 4

private fun Char.isHexDigit(): Boolean =
    isDigit() || this in 'a'..'f' || this in 'A'..'F'

internal fun String.isIpv4Literal(): Boolean {
    val parts = split(".")
    if (parts.size != IPV4_OCTET_COUNT) return false
    return parts.all { part ->
        part.isNotEmpty() &&
            part.all { it.isDigit() } &&
            (part.toIntOrNull() ?: return false) in 0..255
    }
}

internal fun String.isIpv6Literal(): Boolean {
    val candidate = trim()
    if (!candidate.contains(":")) return false
    val bare = if (candidate.startsWith("[") && candidate.endsWith("]"))
        candidate.substring(1, candidate.length - 1) else candidate
    val zoneIdx = bare.indexOf('%')
    val addrPart = if (zoneIdx >= 0) bare.substring(0, zoneIdx) else bare
    if (!addrPart.all { it.isHexDigit() || it == ':' || it == '.' }) return false
    return validateIpv6Structure(addrPart)
}

private fun validateIpv6Structure(addr: String): Boolean {
    val halves = addr.split("::")
    if (halves.size > 2) return false
    val hasDoubleColon = halves.size == 2

    val left = if (halves[0].isEmpty()) emptyList() else halves[0].split(":")
    val right = if (hasDoubleColon && halves[1].isNotEmpty()) halves[1].split(":") else emptyList()
    val allGroups = left + right

    val last = allGroups.lastOrNull()
    val hasEmbeddedIpv4 = last?.contains('.') == true
    val expectedHexGroups = if (hasEmbeddedIpv4) IPV6_HEX_GROUPS_WITH_IPV4 else IPV6_HEX_GROUP_COUNT

    if (hasEmbeddedIpv4) {
        if (!requireNotNull(last).isIpv4Literal()) return false
        val hexGroups = allGroups.dropLast(1)
        if (!hasDoubleColon && hexGroups.size != expectedHexGroups) return false
        if (hasDoubleColon && hexGroups.size >= expectedHexGroups) return false
        return hexGroups.all { it.isValidHexGroup() }
    }

    if (!hasDoubleColon && allGroups.size != expectedHexGroups) return false
    if (hasDoubleColon && allGroups.size >= expectedHexGroups) return false
    return allGroups.all { it.isValidHexGroup() }
}

private fun String.isValidHexGroup(): Boolean =
    isNotEmpty() && length <= MAX_IPV6_HEX_GROUP_LENGTH && all { it.isHexDigit() }
