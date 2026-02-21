package com.mustafadakhel.oag.http

import com.mustafadakhel.oag.DEFAULT_HTTP_PORT
import com.mustafadakhel.oag.DEFAULT_HTTPS_PORT
import com.mustafadakhel.oag.SCHEME_HTTP
import com.mustafadakhel.oag.SCHEME_HTTPS
import com.mustafadakhel.oag.VALID_PORT_RANGE

import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.util.Locale

fun parseAbsoluteTarget(target: String): ParsedTarget {
    val uri = runCatching { URI(target) }
        .getOrElse { throw IllegalArgumentException("Invalid absolute-form target", it) }
    val scheme = requireNotNull(uri.scheme) { "Missing scheme in absolute-form" }
    require(scheme.equals(SCHEME_HTTP, ignoreCase = true) || scheme.equals(SCHEME_HTTPS, ignoreCase = true)) {
        "Unsupported scheme $scheme"
    }
    require(uri.rawUserInfo.isNullOrBlank()) { "Userinfo is not allowed in absolute-form target" }
    require(uri.rawFragment.isNullOrBlank()) { "Fragment is not allowed in absolute-form target" }
    val host = requireNotNull(uri.host) { "Missing host in absolute-form" }
    require(!host.contains("%")) { "IPv6 zone identifiers are not allowed in absolute-form target" }
    require(host.isValidParsedHost()) { "Invalid host in absolute-form target" }
    val port = if (uri.port == -1) scheme.defaultPort() else uri.port
    require(port in VALID_PORT_RANGE) { "Invalid absolute-form port" }
    val path = if (uri.rawPath.isNullOrBlank()) "/" else uri.rawPath
    val query = uri.rawQuery
    val fullPath = if (query.isNullOrBlank()) path else "$path?$query"
    require(!fullPath.any(Char::isWhitespace)) { "Path must not contain whitespace" }
    require(!fullPath.contains("\\")) { "Path must not contain backslashes" }

    return ParsedTarget(
        scheme = scheme.lowercase(Locale.ROOT),
        host = host,
        port = port,
        path = fullPath
    )
}

fun isIpLiteralHost(host: String): Boolean =
    host.isIpv4Literal() || host.isIpv6Literal()

fun parseAuthorityTarget(authority: String): ParsedTarget {
    val trimmed = authority.trim()
    require(!trimmed.contains("@")) { "Userinfo is not allowed in authority-form" }
    if (trimmed.startsWith("[")) {
        val closing = trimmed.indexOf(']')
        require(closing != -1) { "Invalid authority-form" }
        val host = trimmed.substring(1, closing)
        val rest = trimmed.substring(closing + 1)
        require(rest.startsWith(":")) { "Invalid authority-form" }
        val port = requireNotNull(rest.substring(1).toIntOrNull()) { "Invalid authority port" }
        require(port in VALID_PORT_RANGE) { "Invalid authority port" }
        require(!host.contains("%")) { "IPv6 zone identifiers are not allowed in authority-form" }
        require(host.isIpv6Literal()) { "Invalid authority host" }
        require(host.isValidAuthorityHost()) { "Invalid authority host" }
        return ParsedTarget(SCHEME_HTTPS, host, port, "")
    }

    val parts = trimmed.split(":")
    require(parts.size == 2) { "Invalid authority-form" }
    val (host, portStr) = parts
    val port = requireNotNull(portStr.toIntOrNull()) { "Invalid authority port" }
    require(port in VALID_PORT_RANGE) { "Invalid authority port" }
    require(host.isNotBlank()) { "Missing authority host" }
    require(host.isValidAuthorityHost()) { "Invalid authority host" }

    return ParsedTarget(
        scheme = SCHEME_HTTPS,
        host = host,
        port = port,
        path = ""
    )
}

fun defaultPortForScheme(scheme: String): Int = when (scheme.lowercase(Locale.ROOT)) {
    SCHEME_HTTP -> DEFAULT_HTTP_PORT
    SCHEME_HTTPS -> DEFAULT_HTTPS_PORT
    else -> error("Unsupported scheme: $scheme")
}

private fun String.defaultPort(): Int = defaultPortForScheme(this)

private val IP_OCTET_RANGE = 0..255

private fun String.isIpv4Literal(): Boolean {
    val parts = split(".")
    if (parts.size != 4) return false
    return parts.all { part ->
        part.isNotEmpty() &&
            part.all { it.isDigit() } &&
            part.toIntOrNull() != null &&
            part.toInt() in IP_OCTET_RANGE
    }
}

private fun String.isIpv6Literal(): Boolean {
    val candidate = trim()
    if (!candidate.contains(":")) return false
    return runCatching { InetAddress.getByName(candidate) }
        .getOrNull() is Inet6Address
}

private fun String.isValidAuthorityHost(): Boolean {
    if (isBlank()) return false
    if (any { it.isWhitespace() }) return false
    if (contains("/") || contains("?") || contains("#")) return false
    if (!isValidParsedHost()) return false
    return true
}

private const val MAX_HOSTNAME_LENGTH = 253
private const val MAX_LABEL_LENGTH = 63
private val HOSTNAME_LABEL_REGEX = Regex("^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\$")

private fun String.isValidParsedHost(): Boolean {
    if (isIpv6Literal() || isIpv4Literal()) return true
    if (isBlank()) return false
    val trimmed = trimEnd('.')
    if (trimmed.isEmpty()) return false
    if (trimmed.length > MAX_HOSTNAME_LENGTH) return false
    val labels = trimmed.split('.')
    return labels.all { label ->
        label.length in 1..MAX_LABEL_LENGTH && label.matches(HOSTNAME_LABEL_REGEX)
    }
}
