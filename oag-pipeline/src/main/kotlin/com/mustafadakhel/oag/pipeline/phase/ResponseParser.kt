package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.HTTP_TOKEN_REGEX
import com.mustafadakhel.oag.pipeline.LINE_PARTS_REGEX
import com.mustafadakhel.oag.pipeline.hasInvalidHeaderValueChars

private val VALID_STATUS_CODE_RANGE = 100..599
private val REDIRECT_STATUS_RANGE = 300..399
private val INFORMATIONAL_STATUS_RANGE = 100..199
private const val STATUS_NO_CONTENT = 204
private const val STATUS_NOT_MODIFIED = 304

fun parseStatusCode(statusLine: String): Int {
    val parts = statusLine.trim().split(LINE_PARTS_REGEX)
    require(parts.size >= 2) { "Invalid upstream status line" }
    require(parts[0] == HttpConstants.HTTP_1_1 || parts[0] == HttpConstants.HTTP_1_0) { "Invalid upstream status line" }
    require(parts[1].length == 3 && parts[1].all(Char::isDigit)) { "Invalid upstream status code" }
    val statusCode = parts[1].toInt()
    require(statusCode in VALID_STATUS_CODE_RANGE) { "Invalid upstream status code" }
    return statusCode
}

fun validateHeaderLine(line: String, messagePrefix: String) {
    require(line.isNotEmpty()) { "$messagePrefix: empty line" }
    require(!line.first().isWhitespace()) { "$messagePrefix: leading whitespace" }
    val idx = line.indexOf(':')
    require(idx > 0) { "$messagePrefix: missing colon" }
    val name = line.substring(0, idx).trim()
    require(name.isNotBlank()) { "$messagePrefix: blank name" }
    require(name.matches(HTTP_TOKEN_REGEX)) { "$messagePrefix: invalid name token" }
    val value = line.substring(idx + 1).trim()
    require(!value.hasInvalidHeaderValueChars()) { "$messagePrefix: invalid value" }
}

fun isRedirect(statusCode: Int?): Boolean =
    statusCode != null && statusCode in REDIRECT_STATUS_RANGE

fun responseHasBody(statusCode: Int, requestMethod: String): Boolean {
    if (requestMethod.equals(HttpConstants.METHOD_HEAD, ignoreCase = true)) return false
    if (statusCode in INFORMATIONAL_STATUS_RANGE || statusCode == STATUS_NO_CONTENT || statusCode == STATUS_NOT_MODIFIED) return false
    return true
}
