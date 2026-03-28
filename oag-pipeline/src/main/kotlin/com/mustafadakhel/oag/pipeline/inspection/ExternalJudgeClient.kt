package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.OutboundResult
import com.mustafadakhel.oag.SafeOutboundClient
import com.mustafadakhel.oag.computeHmacSha256
import com.mustafadakhel.oag.http.HttpConstants

import kotlinx.serialization.json.Json

import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse

class ExternalJudgeClient(
    private val client: SafeOutboundClient,
    private val endpointUrl: String,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    private val signingSecret: String? = null,
    private val maxResponseBytes: Int = DEFAULT_MAX_RESPONSE_BYTES,
    validateUrl: Boolean = true
) {
    private val endpointUri = URI(endpointUrl)
    private val responseJson = Json { ignoreUnknownKeys = true }

    init {
        if (validateUrl) {
            val validation = client.validateTarget(endpointUri)
            require(validation is OutboundResult.Success) {
                "Judge endpoint is not reachable: $endpointUrl"
            }
        }
    }

    fun invoke(request: JudgeRequest): JudgeResult {
        val bodyText = responseJson.encodeToString(request)
        val bodyBytes = bodyText.toByteArray(Charsets.UTF_8)

        val requestBuilder = HttpRequest.newBuilder(endpointUri)
            .header(HttpConstants.CONTENT_TYPE_HEADER, HttpConstants.APPLICATION_JSON)
            .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes))

        if (signingSecret != null) {
            val signature = computeHmacSha256(signingSecret, bodyBytes)
            requestBuilder.header(HttpConstants.OAG_SIGNATURE, "${CryptoConstants.SIGNATURE_PREFIX_SHA256}$signature")
        }

        val httpRequest = requestBuilder.build()
        val startMs = System.currentTimeMillis()

        return when (val result = client.execute(httpRequest, HttpResponse.BodyHandlers.ofInputStream(), timeoutMs)) {
            is OutboundResult.Blocked -> {
                val latency = System.currentTimeMillis() - startMs
                JudgeResult(score = 0.0, decision = JudgeDecision.ABSTAIN, source = "external", latencyMs = latency, error = "blocked: ${result.reason}")
            }
            is OutboundResult.Failure -> {
                val latency = System.currentTimeMillis() - startMs
                JudgeResult(score = 0.0, decision = JudgeDecision.ABSTAIN, source = "external", latencyMs = latency, error = result.error.message)
            }
            is OutboundResult.Success -> {
                val latency = System.currentTimeMillis() - startMs
                val response = result.value
                if (response.statusCode() !in 200..299) {
                    return JudgeResult(score = 0.0, decision = JudgeDecision.ABSTAIN, source = "external", latencyMs = latency, error = "HTTP ${response.statusCode()}")
                }
                val bytes = response.body().readNBytes(maxResponseBytes + 1)
                if (bytes.size > maxResponseBytes) {
                    return JudgeResult(score = 0.0, decision = JudgeDecision.ABSTAIN, source = "external", latencyMs = latency, error = "response exceeds $maxResponseBytes bytes")
                }
                val responseText = String(bytes, Charsets.UTF_8)
                val judgeResponse = runCatching {
                    responseJson.decodeFromString<JudgeResponse>(responseText)
                }.getOrElse {
                    return JudgeResult(score = 0.0, decision = JudgeDecision.ABSTAIN, source = "external", latencyMs = latency, error = "invalid response JSON: ${it.message}")
                }
                JudgeResult(
                    score = judgeResponse.score.coerceIn(0.0, 1.0),
                    decision = JudgeDecision.fromLabel(judgeResponse.decision),
                    source = "external",
                    latencyMs = latency,
                    reason = judgeResponse.reason
                )
            }
        }
    }

    companion object {
        private const val DEFAULT_TIMEOUT_MS = 5_000L
        private const val DEFAULT_MAX_RESPONSE_BYTES = 65_536
    }
}
