package com.mustafadakhel.oag.proxy.admin

import com.mustafadakhel.oag.http.HttpConstants

import java.io.OutputStream

private fun StringBuilder.appendHeader(name: String, value: Any): StringBuilder =
    append(name).append(HttpConstants.HEADER_SEPARATOR).append(value).append(HttpConstants.CRLF)

internal fun writeAdminResponse(output: OutputStream, statusCode: Int, contentType: String, body: String) {
    val bodyBytes = body.toByteArray(Charsets.UTF_8)
    val statusText = HttpConstants.statusText(statusCode)
    val head = buildString {
        append("HTTP/1.1 ").append(statusCode).append(' ').append(statusText).append(HttpConstants.CRLF)
        appendHeader(HttpConstants.CONTENT_TYPE_HEADER, contentType)
        appendHeader(HttpConstants.CONTENT_LENGTH, bodyBytes.size)
        appendHeader(HttpConstants.CONNECTION, HttpConstants.CONNECTION_CLOSE)
        append(HttpConstants.CRLF)
    }
    output.write(head.toByteArray(Charsets.US_ASCII))
    output.write(bodyBytes)
    output.flush()
}
