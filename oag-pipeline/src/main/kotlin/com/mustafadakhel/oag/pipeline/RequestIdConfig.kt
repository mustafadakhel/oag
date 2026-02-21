package com.mustafadakhel.oag.pipeline

import java.util.UUID

private const val DEFAULT_REQUEST_ID_HEADER = "X-Request-Id"

data class RequestIdConfig(
    val injectRequestId: Boolean = false,
    val requestIdHeader: String = DEFAULT_REQUEST_ID_HEADER
)

@JvmInline
value class RequestId(val value: String) {
    companion object {
        fun generate(): RequestId = RequestId(UUID.randomUUID().toString())
    }
}
