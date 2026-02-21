package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.http.defaultPortForScheme

import java.util.Locale

const val MAX_HTTP_LINE_LENGTH = 8 * 1024
const val DEFAULT_BODY_BUFFER_LIMIT = 1L * 1024 * 1024
const val DEFAULT_RESPONSE_SCAN_LIMIT = 64L * 1024
const val START_OF_MESSAGE_CHAR_LIMIT = 500
const val MAX_RESPONSE_HEADER_LINES = 256
const val MAX_CHUNK_SIZE = 64L * 1024 * 1024
const val MAX_BUFFER_REQUEST_BODY_BYTES = 10L * 1024 * 1024
const val SSE_CONTENT_TYPE = "text/event-stream"
const val DEFAULT_DENY_THRESHOLD = 0.5
const val DEFAULT_MIN_VALUE_LENGTH = 40
const val DEFAULT_ENTROPY_THRESHOLD = 4.0

val LINE_PARTS_REGEX = Regex("\\s+")
val HEX_TOKEN_REGEX = Regex("^[0-9A-Fa-f]+$")
val SINGLETON_FRAMING_HEADERS = setOf(HttpConstants.CONTENT_LENGTH, HttpConstants.TRANSFER_ENCODING)
val HTTP_TOKEN_REGEX = Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

val REQUEST_HOP_BY_HOP_HEADERS = setOf(
    HttpConstants.CONNECTION,
    HttpConstants.KEEP_ALIVE,
    HttpConstants.PROXY_AUTHENTICATE,
    HttpConstants.PROXY_AUTHORIZATION,
    HttpConstants.PROXY_CONNECTION,
    HttpConstants.TE,
    HttpConstants.TRAILER,
    HttpConstants.TRANSFER_ENCODING,
    HttpConstants.UPGRADE
)

val RESPONSE_HOP_BY_HOP_HEADERS = setOf(
    HttpConstants.CONNECTION,
    HttpConstants.KEEP_ALIVE,
    HttpConstants.PROXY_AUTHENTICATE,
    HttpConstants.PROXY_CONNECTION,
    HttpConstants.TE,
    HttpConstants.TRAILER,
    HttpConstants.UPGRADE
)

fun String.toHeaderCase(): String =
    split('-').joinToString("-") { part ->
        part.lowercase(Locale.ROOT).replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
    }

fun hostHeaderValue(target: ParsedTarget): String {
    val defaultPort = defaultPortForScheme(target.scheme)
    val host = target.host.toHostHeaderHost()
    return if (defaultPort == target.port) host else "$host:${target.port}"
}

private fun String.toHostHeaderHost(): String =
    if (contains(":") && !(startsWith("[") && endsWith("]"))) "[$this]" else this

fun String.hasFinalChunkedEncoding(): Boolean {
    val codings = split(",").map { it.trim() }
    if (codings.isEmpty() || codings.any { it.isEmpty() }) return false
    return codings.last().equals("chunked", ignoreCase = true)
}

fun String.hasInvalidHeaderValueChars(): Boolean =
    any { ch ->
        val code = ch.code
        code == 0x7F || (code < 0x20 && ch != '\t') || code > 0x7E
    }

fun buildUpstreamRequestHead(
    method: String,
    path: String,
    version: String,
    headers: Map<String, String>
): String = buildString {
    append(method).append(' ').append(path).append(' ').append(version).append(HttpConstants.CRLF)
    headers.forEach { (name, value) ->
        append(name.toHeaderCase()).append(HttpConstants.HEADER_SEPARATOR).append(value).append(HttpConstants.CRLF)
    }
    append(HttpConstants.CRLF)
}
