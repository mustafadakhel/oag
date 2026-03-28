package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.OutboundResult
import com.mustafadakhel.oag.SafeOutboundClient
import com.mustafadakhel.oag.computeHmacSha256
import com.mustafadakhel.oag.http.HttpConstants

import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.atomic.AtomicInteger

data class ExternalVerificationResult(
    val score: Double?,
    val error: String? = null
)

class ExternalVerifier(
    private val client: SafeOutboundClient,
    private val endpointUrl: String,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    private val signingSecret: String? = null,
    private val maxConsecutiveFailures: Int = DEFAULT_MAX_CONSECUTIVE_FAILURES
) {
    private val consecutiveFailures = AtomicInteger(0)

    val circuitOpen: Boolean get() = consecutiveFailures.get() >= maxConsecutiveFailures

    fun verify(responseText: String, requestText: String? = null): ExternalVerificationResult {
        if (circuitOpen) {
            return ExternalVerificationResult(score = null, error = "circuit_open")
        }

        val bodyJson = buildRequestJson(responseText, requestText)
        val bodyBytes = bodyJson.toByteArray(Charsets.UTF_8)

        val requestBuilder = HttpRequest.newBuilder(URI(endpointUrl))
            .header(HttpConstants.CONTENT_TYPE_HEADER, HttpConstants.APPLICATION_JSON)
            .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes))

        if (signingSecret != null) {
            val signature = computeHmacSha256(signingSecret, bodyBytes)
            requestBuilder.header(HttpConstants.OAG_SIGNATURE, "${CryptoConstants.SIGNATURE_PREFIX_SHA256}$signature")
        }

        val request = requestBuilder.build()

        return when (val result = client.execute(request, HttpResponse.BodyHandlers.ofString(), timeoutMs)) {
            is OutboundResult.Blocked -> {
                ExternalVerificationResult(score = null, error = "blocked: ${result.reason}")
            }
            is OutboundResult.Failure -> {
                consecutiveFailures.incrementAndGet()
                ExternalVerificationResult(score = null, error = result.error.message)
            }
            is OutboundResult.Success -> {
                consecutiveFailures.set(0)
                parseScoreResponse(result.value.body())
            }
        }
    }

    companion object {
        private const val DEFAULT_TIMEOUT_MS = 5_000L
        private const val DEFAULT_MAX_CONSECUTIVE_FAILURES = 5
    }
}

private fun buildRequestJson(responseText: String, requestText: String?): String {
    val escaped = escapeJsonString(responseText)
    return if (requestText != null) {
        """{"response_text":"$escaped","request_text":"${escapeJsonString(requestText)}"}"""
    } else {
        """{"response_text":"$escaped"}"""
    }
}

private fun escapeJsonString(s: String): String = buildString(s.length + 16) {
    for (c in s) {
        when (c) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (c.code < 0x20) append("\\u${c.code.toString(16).padStart(4, '0')}") else append(c)
        }
    }
}

private val SCORE_PATTERN = Regex(""""score"\s*:\s*(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)""")

private fun parseScoreResponse(body: String): ExternalVerificationResult {
    val match = SCORE_PATTERN.find(body)
        ?: return ExternalVerificationResult(score = null, error = "no score field in response")
    val score = match.groupValues[1].toDoubleOrNull()
        ?: return ExternalVerificationResult(score = null, error = "invalid score value")
    return ExternalVerificationResult(score = score.coerceIn(0.0, 1.0))
}
