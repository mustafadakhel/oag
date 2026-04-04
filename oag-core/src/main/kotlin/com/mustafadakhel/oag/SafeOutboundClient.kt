package com.mustafadakhel.oag

import com.mustafadakhel.oag.http.isIpLiteralHost

import java.net.InetAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

sealed interface OutboundResult<out T> {
    data class Success<T>(val value: T) : OutboundResult<T>
    data class Failure(val error: Throwable) : OutboundResult<Nothing>
    data class Blocked(val reason: String) : OutboundResult<Nothing>
}

class SafeOutboundClient(
    private val connectTimeoutMs: Long = DEFAULT_CONNECT_TIMEOUT_MS
) {
    private val httpClient: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(connectTimeoutMs))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()

    fun validateTarget(uri: URI): OutboundResult<InetAddress> {
        val host = uri.host ?: return OutboundResult.Blocked("URL has no host")
        if (isIpLiteralHost(host)) {
            return OutboundResult.Blocked("IP literal hosts are not allowed: $host")
        }
        val resolved = runCatching { InetAddress.getByName(host) }.getOrElse {
            return OutboundResult.Failure(it)
        }
        if (resolved.isSpecialPurposeAddress()) {
            return OutboundResult.Blocked("Host resolves to special-purpose address: $host -> ${resolved.hostAddress}")
        }
        return OutboundResult.Success(resolved)
    }

    fun <T> execute(
        request: HttpRequest,
        bodyHandler: HttpResponse.BodyHandler<T>,
        timeoutMs: Long? = null
    ): OutboundResult<HttpResponse<T>> {
        val effectiveRequest = if (timeoutMs != null) {
            HttpRequest.newBuilder(request.uri())
                .method(request.method(), request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()))
                .timeout(Duration.ofMillis(timeoutMs))
                .also { b -> request.headers().map().forEach { (name, values) -> values.forEach { b.header(name, it) } } }
                .build()
        } else request
        return runCatching { httpClient.send(effectiveRequest, bodyHandler) }.fold(
            onSuccess = { OutboundResult.Success(it) },
            onFailure = { OutboundResult.Failure(it) }
        )
    }

    companion object {
        private const val DEFAULT_CONNECT_TIMEOUT_MS = 5_000L
    }
}
