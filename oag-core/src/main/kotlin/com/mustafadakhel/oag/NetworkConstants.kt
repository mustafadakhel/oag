package com.mustafadakhel.oag

const val DEFAULT_HTTP_PORT = 80
const val DEFAULT_HTTPS_PORT = 443
const val SCHEME_HTTP = "http"
const val SCHEME_HTTPS = "https"
val VALID_PORT_RANGE = 1..65535

val HTTP_SUCCESS_RANGE = 200..299

// Policy action labels (shared across modules that can't depend on oag-policy)
const val ACTION_ALLOW = "allow"
const val ACTION_DENY = "deny"

// Integrity check status labels (shared across audit, telemetry, proxy)
const val STATUS_PASS = "pass"
const val STATUS_FAIL = "fail"

// Hop-by-hop / framing headers (lowercase, shared across policy validation and proxy)
const val HEADER_HOST = "host"
const val HEADER_CONTENT_LENGTH = "content-length"
const val HEADER_TRANSFER_ENCODING = "transfer-encoding"
const val HEADER_TE = "te"
const val HEADER_TRAILER = "trailer"
const val HEADER_UPGRADE = "upgrade"
const val HEADER_CONNECTION = "connection"
const val HEADER_PROXY_CONNECTION = "proxy-connection"

const val HEADER_CONTENT_TYPE = "Content-Type"
const val HEADER_USER_AGENT = "User-Agent"
const val CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded"

val FORBIDDEN_REWRITE_HEADERS = setOf(
    HEADER_HOST, HEADER_CONTENT_LENGTH, HEADER_TRANSFER_ENCODING,
    HEADER_TE, HEADER_TRAILER, HEADER_UPGRADE, HEADER_CONNECTION, HEADER_PROXY_CONNECTION
)

// HTTP methods
const val METHOD_GET = "GET"
const val METHOD_HEAD = "HEAD"
const val METHOD_POST = "POST"
const val METHOD_PUT = "PUT"
const val METHOD_DELETE = "DELETE"
const val METHOD_PATCH = "PATCH"
const val METHOD_OPTIONS = "OPTIONS"
const val METHOD_TRACE = "TRACE"
const val METHOD_CONNECT = "CONNECT"

val ALL_HTTP_METHODS = setOf(
    METHOD_GET, METHOD_HEAD, METHOD_POST, METHOD_PUT, METHOD_DELETE,
    METHOD_PATCH, METHOD_OPTIONS, METHOD_TRACE, METHOD_CONNECT
)
