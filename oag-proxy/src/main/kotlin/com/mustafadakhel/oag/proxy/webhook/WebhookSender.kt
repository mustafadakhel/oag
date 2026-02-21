package com.mustafadakhel.oag.proxy.webhook

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.HTTP_SUCCESS_RANGE
import com.mustafadakhel.oag.SCHEME_HTTP
import com.mustafadakhel.oag.SCHEME_HTTPS
import com.mustafadakhel.oag.RetryExhaustedException
import com.mustafadakhel.oag.RetryPolicy
import com.mustafadakhel.oag.isSpecialPurposeAddress
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.computeHmacSha256
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.proxy.ProxyDefaults
import com.mustafadakhel.oag.telemetry.DebugLogger
import com.mustafadakhel.oag.withSuspendRetry

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

import java.net.InetAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant

enum class WebhookEventType {
    CIRCUIT_OPEN,
    RELOAD_FAILED,
    INJECTION_DETECTED,
    CREDENTIAL_DETECTED,
    INTEGRITY_DRIFT,
    ADMIN_DENIED;

    companion object {
        private val BY_LABEL = entries.associateBy { it.label() }

        fun fromLabel(label: String): WebhookEventType? = BY_LABEL[label]
    }
}

internal data class WebhookConfig(
    val url: String,
    val events: Set<WebhookEventType> = emptySet(),
    val timeoutMs: Int = ProxyDefaults.WEBHOOK_TIMEOUT_MS,
    val signingSecret: String? = null,
    val maxRetries: Int = DEFAULT_MAX_RETRIES
) {
    companion object {
        const val DEFAULT_MAX_RETRIES = 3
    }
}

@Serializable
internal data class WebhookPayload(
    val eventType: String,
    val timestamp: String = Instant.now().toString(),
    val data: Map<String, JsonElement>
)

private val ALLOWED_WEBHOOK_SCHEMES = setOf(SCHEME_HTTP, SCHEME_HTTPS)
private val webhookJson = Json { encodeDefaults = true }

internal class WebhookSender(
    private val config: WebhookConfig,
    private val debugLogger: DebugLogger = DebugLogger.NOOP,
    validateUrl: Boolean = true
) {
    init {
        if (validateUrl) {
            val uri = URI(config.url)
            require(uri.scheme in ALLOWED_WEBHOOK_SCHEMES) { "webhook URL scheme must be http or https, got: ${uri.scheme}" }
            val host = requireNotNull(uri.host) { "webhook URL must have a host" }
            val resolved = InetAddress.getByName(host)
            require(!resolved.isSpecialPurposeAddress()) {
                "webhook URL resolves to private/reserved address: $host -> ${resolved.hostAddress}"
            }
        }
    }

    private val webhookUri = URI(config.url)

    private val httpClient: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(config.timeoutMs.toLong()))
        .build()

    fun shouldSend(eventType: String): Boolean {
        if (config.events.isEmpty()) return true
        val parsed = WebhookEventType.fromLabel(eventType)
        if (parsed == null) {
            debugLogger.log("unknown webhook event type '$eventType' — not in WebhookEventType enum, dropping")
            return false
        }
        return parsed in config.events
    }

    suspend fun send(payload: WebhookPayload) {
        if (!shouldSend(payload.eventType)) return
        val bodyBytes = webhookJson.encodeToString(payload).toByteArray(Charsets.UTF_8)

        try {
            withSuspendRetry(
                RetryPolicy(
                    maxAttempts = config.maxRetries,
                    baseDelayMs = RETRY_BASE_DELAY_MS,
                    maxDelayMs = RETRY_MAX_DELAY_MS
                ),
                onFailure = { attempt, e ->
                    debugLogger.log { "webhook attempt $attempt/${config.maxRetries} failed url=${config.url}: ${e.message}" }
                }
            ) {
                trySend(bodyBytes)
            }
        } catch (e: RetryExhaustedException) {
            debugLogger.log { "webhook dead-letter event=${payload.eventType} url=${config.url}: ${e.lastError.message}" }
        }
    }

    private fun trySend(bodyBytes: ByteArray) {
        val requestBuilder = HttpRequest.newBuilder()
            .uri(webhookUri)
            .timeout(Duration.ofMillis(config.timeoutMs.toLong()))
            .header(HttpConstants.CONTENT_TYPE_HEADER, HttpConstants.APPLICATION_JSON)
            .header(HttpConstants.USER_AGENT, WEBHOOK_USER_AGENT)
            .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes))

        if (config.signingSecret != null) {
            val signature = computeHmacSha256(config.signingSecret, bodyBytes)
            requestBuilder.header(HttpConstants.OAG_SIGNATURE, "${CryptoConstants.SIGNATURE_PREFIX_SHA256}$signature")
        }

        val response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.discarding())
        if (response.statusCode() !in HTTP_SUCCESS_RANGE) {
            throw WebhookSendException("HTTP ${response.statusCode()} from ${config.url}")
        }
    }

    companion object {
        private const val WEBHOOK_USER_AGENT = "oag-webhook/1.0"
        private const val RETRY_BASE_DELAY_MS = 500L
        private const val RETRY_MAX_DELAY_MS = 5_000L
    }
}

internal class WebhookSendException(message: String) : RuntimeException(message)
