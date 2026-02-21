package com.mustafadakhel.oag.http

import com.mustafadakhel.oag.CONTENT_TYPE_FORM_URLENCODED as CORE_FORM_URLENCODED
import com.mustafadakhel.oag.HEADER_CONNECTION as CORE_CONNECTION
import com.mustafadakhel.oag.HEADER_CONTENT_TYPE as CORE_CONTENT_TYPE_HEADER
import com.mustafadakhel.oag.HEADER_CONTENT_LENGTH as CORE_CONTENT_LENGTH
import com.mustafadakhel.oag.HEADER_HOST as CORE_HOST
import com.mustafadakhel.oag.HEADER_PROXY_CONNECTION as CORE_PROXY_CONNECTION
import com.mustafadakhel.oag.HEADER_TE as CORE_TE
import com.mustafadakhel.oag.HEADER_TRAILER as CORE_TRAILER
import com.mustafadakhel.oag.HEADER_TRANSFER_ENCODING as CORE_TRANSFER_ENCODING
import com.mustafadakhel.oag.HEADER_UPGRADE as CORE_UPGRADE
import com.mustafadakhel.oag.HEADER_USER_AGENT as CORE_USER_AGENT
import com.mustafadakhel.oag.METHOD_CONNECT as CORE_METHOD_CONNECT
import com.mustafadakhel.oag.METHOD_GET as CORE_METHOD_GET
import com.mustafadakhel.oag.METHOD_HEAD as CORE_METHOD_HEAD
import com.mustafadakhel.oag.METHOD_POST as CORE_METHOD_POST

object HttpConstants {
    // Header names (hop-by-hop headers delegate to shared NetworkConstants)
    const val CONTENT_LENGTH = CORE_CONTENT_LENGTH
    const val CONTENT_TYPE = "content-type"
    const val TRANSFER_ENCODING = CORE_TRANSFER_ENCODING
    const val HOST = CORE_HOST
    const val CONNECTION = CORE_CONNECTION
    const val UPGRADE = CORE_UPGRADE
    const val LOCATION = "location"
    const val TRACEPARENT = "traceparent"
    const val PROXY_AUTHENTICATE = "proxy-authenticate"
    const val PROXY_AUTHORIZATION = "proxy-authorization"
    const val PROXY_CONNECTION = CORE_PROXY_CONNECTION
    const val OAG_SIGNATURE = "x-oag-signature"
    const val OAG_TIMESTAMP = "x-oag-timestamp"
    const val OAG_AGENT_ID = "x-oag-agent-id"
    const val TE = CORE_TE
    const val TRAILER = CORE_TRAILER
    const val KEEP_ALIVE = "keep-alive"

    // Wire format
    const val CRLF = "\r\n"
    const val HEADER_SEPARATOR = ": "

    // HTTP methods (delegating to shared NetworkConstants)
    const val METHOD_CONNECT = CORE_METHOD_CONNECT
    const val METHOD_GET = CORE_METHOD_GET
    const val METHOD_HEAD = CORE_METHOD_HEAD
    const val METHOD_POST = CORE_METHOD_POST

    // HTTP versions
    const val HTTP_1_0 = "HTTP/1.0"
    const val HTTP_1_1 = "HTTP/1.1"

    // Additional header names (title-case for HTTP/1.1 wire format)
    const val CONTENT_TYPE_HEADER = CORE_CONTENT_TYPE_HEADER
    const val USER_AGENT = CORE_USER_AGENT

    // Content types
    const val APPLICATION_JSON = "application/json"
    const val FORM_URLENCODED = CORE_FORM_URLENCODED
    const val TEXT_PLAIN = "text/plain"
    const val PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

    // Connection header values
    const val CONNECTION_CLOSE = "close"
    const val CONNECTION_KEEP_ALIVE = "keep-alive"
    const val UPGRADE_WEBSOCKET = "websocket"

    // Pre-built responses
    val CONNECT_ESTABLISHED_RESPONSE = "HTTP/1.1 200 Connection Established$CRLF$CRLF".toByteArray(Charsets.US_ASCII)

    val STATUS_TEXT = mapOf(
        100 to "Continue",
        101 to "Switching Protocols",
        200 to "OK",
        201 to "Created",
        202 to "Accepted",
        203 to "Non-Authoritative Information",
        204 to "No Content",
        205 to "Reset Content",
        206 to "Partial Content",
        207 to "Multi-Status",
        301 to "Moved Permanently",
        302 to "Found",
        303 to "See Other",
        304 to "Not Modified",
        307 to "Temporary Redirect",
        308 to "Permanent Redirect",
        400 to "Bad Request",
        401 to "Unauthorized",
        403 to "Forbidden",
        404 to "Not Found",
        405 to "Method Not Allowed",
        406 to "Not Acceptable",
        407 to "Proxy Authentication Required",
        408 to "Request Timeout",
        409 to "Conflict",
        410 to "Gone",
        411 to "Length Required",
        412 to "Precondition Failed",
        413 to "Content Too Large",
        414 to "URI Too Long",
        415 to "Unsupported Media Type",
        416 to "Range Not Satisfiable",
        417 to "Expectation Failed",
        422 to "Unprocessable Content",
        429 to "Too Many Requests",
        500 to "Internal Server Error",
        501 to "Not Implemented",
        502 to "Bad Gateway",
        503 to "Service Unavailable",
        504 to "Gateway Timeout"
    )

    fun statusText(code: Int): String = STATUS_TEXT[code] ?: when (code) {
        in 100..199 -> "Informational"
        in 200..299 -> "OK"
        in 300..399 -> "Redirection"
        in 400..499 -> "Client Error"
        in 500..599 -> "Server Error"
        else -> "Unknown"
    }
}
