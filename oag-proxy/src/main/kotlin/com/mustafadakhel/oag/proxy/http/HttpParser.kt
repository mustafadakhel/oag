package com.mustafadakhel.oag.proxy.http

import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.VALID_PORT_RANGE
import com.mustafadakhel.oag.pipeline.HTTP_TOKEN_REGEX
import com.mustafadakhel.oag.pipeline.LINE_PARTS_REGEX
import com.mustafadakhel.oag.pipeline.SINGLETON_FRAMING_HEADERS
import com.mustafadakhel.oag.pipeline.readLine

import java.io.InputStream
import java.util.Locale

private const val MAX_HEADER_LINES = 256
private const val MAX_HEADER_VALUE_LENGTH = 8192
private val SINGLETON_REQUEST_HEADERS = setOf(HttpConstants.HOST)

internal fun parseHttpRequest(input: InputStream): HttpRequest {
    val requestLine = requireNotNull(readLine(input)) { "Empty request" }
    val parts = requestLine.trim().split(LINE_PARTS_REGEX)
    require(parts.size == 3) { "Invalid request line" }

    val (method, target, version) = parts
    require(method.matches(HTTP_TOKEN_REGEX)) { "Invalid HTTP method token" }
    require(version == HttpConstants.HTTP_1_1 || version == HttpConstants.HTTP_1_0) { "Unsupported HTTP version" }

    val headers = linkedMapOf<String, String>()
    val headerCounts = mutableMapOf<String, Int>()
    var headerLineCount = 0

    while (true) {
        val line = readLine(input) ?: break
        if (line.isEmpty()) break
        require(!line.first().isWhitespace()) { "Invalid header line" }
        headerLineCount += 1
        require(headerLineCount <= MAX_HEADER_LINES) { "Too many headers" }
        val idx = line.indexOf(':')
        require(idx > 0) { "Invalid header line" }
        val name = line.substring(0, idx).trim()
        require(name.isNotBlank()) { "Invalid header name" }
        require(name.matches(HTTP_TOKEN_REGEX)) { "Invalid header name token" }
        val value = line.substring(idx + 1).trim()
        require(value.length <= MAX_HEADER_VALUE_LENGTH) { "Header value too long" }
        val key = name.lowercase(Locale.ROOT)
        val count = (headerCounts[key] ?: 0) + 1
        headerCounts[key] = count
        require(key !in SINGLETON_FRAMING_HEADERS || count <= 1) { "Duplicate framing header: $key" }
        require(key !in SINGLETON_REQUEST_HEADERS || count <= 1) { "Duplicate request header: $key" }
        require(!value.hasInvalidHeaderValueChars()) { "Invalid header value" }
        if (key == HttpConstants.CONTENT_LENGTH) {
            require(value.isNotEmpty() && value.all(Char::isDigit) && value.toLongOrNull() != null) {
                "Invalid content-length"
            }
        }
        val existing = headers[key]
        headers[key] = if (existing != null) "$existing, $value" else value
    }

    require(!headers.containsKey(HttpConstants.CONTENT_LENGTH) || !headers.containsKey(HttpConstants.TRANSFER_ENCODING)) {
        "Conflicting framing headers"
    }
    if (version == HttpConstants.HTTP_1_1) {
        require(headers.containsKey(HttpConstants.HOST)) { "Missing host header" }
        validateHostHeader(headers.getValue(HttpConstants.HOST))
    }

    return HttpRequest(
        method = method,
        target = target,
        version = version,
        headers = headers
    )
}

private fun validateHostHeader(value: String) {
    val trimmed = value.trim()
    require(trimmed.isNotEmpty()) { "Empty host header" }
    require(trimmed.none { it.isWhitespace() }) { "Invalid host header" }
    require(!trimmed.contains("/") && !trimmed.contains("?") && !trimmed.contains("#")) { "Invalid host header" }
    require(!trimmed.contains("@")) { "Invalid host header" }
    val host = if (trimmed.startsWith("[")) {
        val closing = trimmed.indexOf(']')
        require(closing != -1) { "Invalid host header" }
        val remainder = trimmed.substring(closing + 1)
        if (remainder.isNotEmpty()) {
            require(remainder.startsWith(":")) { "Invalid host header" }
            val portText = remainder.substring(1)
            require(portText.isNotEmpty() && portText.all(Char::isDigit)) { "Invalid host header" }
            val port = portText.toIntOrNull()
            require(port != null && port in VALID_PORT_RANGE) { "Invalid host header" }
        }
        trimmed.substring(1, closing)
    } else {
        val parts = trimmed.split(":", limit = 2)
        if (parts.size == 2) {
            val portText = parts[1]
            require(portText.isNotEmpty() && portText.all(Char::isDigit)) { "Invalid host header" }
            val port = portText.toIntOrNull()
            require(port != null && port in VALID_PORT_RANGE) { "Invalid host header" }
        }
        require(!parts[0].contains(":")) { "Invalid host header" }
        parts[0]
    }.trimEnd('.')
    require(host.isNotEmpty()) { "Invalid host header" }
    require(!host.startsWith(".")) { "Invalid host header" }
    require(!host.contains("..")) { "Invalid host header" }
}

private fun String.hasInvalidHeaderValueChars(): Boolean =
    any { ch ->
        val code = ch.code
        // Reject NUL, CR, LF, DEL; allow HTAB, printable ASCII, and obs-text (0x80-0xFF)
        code == 0x00 || code == 0x0D || code == 0x0A || code == 0x7F ||
            (code < 0x20 && code != 0x09)
    }
