package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.policy.core.PolicyErrorResponse

import java.io.OutputStream

private fun StringBuilder.appendHeader(name: String, value: Any): StringBuilder =
    append(name).append(HttpConstants.HEADER_SEPARATOR).append(value).append(HttpConstants.CRLF)

fun writeErrorResponse(output: OutputStream, statusCode: Int) {
    val statusText = HttpConstants.statusText(statusCode)
    val head = buildString {
        append("${HttpConstants.HTTP_1_1} $statusCode $statusText${HttpConstants.CRLF}")
        appendHeader(HttpConstants.CONTENT_LENGTH, 0)
        append(HttpConstants.CRLF)
    }
    output.write(head.toByteArray(Charsets.US_ASCII))
    output.flush()
}

fun writeDenied(output: OutputStream) =
    writeErrorResponse(output, HttpStatus.FORBIDDEN.code)

fun writeBadRequest(output: OutputStream) =
    writeErrorResponse(output, HttpStatus.BAD_REQUEST.code)

fun writeServiceUnavailable(output: OutputStream) =
    writeErrorResponse(output, HttpStatus.SERVICE_UNAVAILABLE.code)

fun writeCustomDenied(output: OutputStream, errorResponse: PolicyErrorResponse) {
    val status = errorResponse.status ?: HttpStatus.FORBIDDEN.code
    val statusText = HttpConstants.statusText(status)
    val bodyBytes = errorResponse.body?.toByteArray(Charsets.UTF_8)
    val contentType = errorResponse.contentType ?: HttpConstants.TEXT_PLAIN
    val head = buildString {
        append("HTTP/1.1 $status $statusText${HttpConstants.CRLF}")
        if (bodyBytes != null && bodyBytes.isNotEmpty()) {
            appendHeader(HttpConstants.CONTENT_TYPE_HEADER, contentType)
            appendHeader(HttpConstants.CONTENT_LENGTH, bodyBytes.size)
        } else {
            appendHeader(HttpConstants.CONTENT_LENGTH, 0)
        }
        append(HttpConstants.CRLF)
    }
    output.write(head.toByteArray(Charsets.US_ASCII))
    if (bodyBytes != null && bodyBytes.isNotEmpty()) {
        output.write(bodyBytes)
    }
    output.flush()
}
