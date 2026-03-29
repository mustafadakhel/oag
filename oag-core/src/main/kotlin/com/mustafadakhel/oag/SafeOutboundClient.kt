/*
 * Copyright 2026 Mustafa Dakhel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
        val uri = request.uri()
        return when (val validation = validateTarget(uri)) {
            is OutboundResult.Blocked -> validation
            is OutboundResult.Failure -> validation
            is OutboundResult.Success -> {
                val pinnedRequest = pinToResolvedAddress(request, validation.value, timeoutMs)
                runCatching { httpClient.send(pinnedRequest, bodyHandler) }.fold(
                    onSuccess = { OutboundResult.Success(it) },
                    onFailure = { OutboundResult.Failure(it) }
                )
            }
        }
    }

    companion object {
        private const val DEFAULT_CONNECT_TIMEOUT_MS = 5_000L
    }
}

private fun pinToResolvedAddress(
    original: HttpRequest,
    resolved: InetAddress,
    timeoutMs: Long?
): HttpRequest {
    val originalUri = original.uri()
    val pinnedUri = URI(
        originalUri.scheme,
        null,
        resolved.hostAddress,
        originalUri.port,
        originalUri.path,
        originalUri.query,
        originalUri.fragment
    )
    val builder = HttpRequest.newBuilder(pinnedUri)
        .method(original.method(), original.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()))

    original.headers().map().forEach { (name, values) ->
        values.forEach { builder.header(name, it) }
    }

    // Ensure Host header reflects original hostname for virtual hosting
    builder.header("Host", originalUri.host + portSuffix(originalUri))

    if (timeoutMs != null) {
        builder.timeout(Duration.ofMillis(timeoutMs))
    } else {
        original.timeout().ifPresent { builder.timeout(it) }
    }

    return builder.build()
}

private fun portSuffix(uri: URI): String =
    if (uri.port > 0) ":${uri.port}" else ""
