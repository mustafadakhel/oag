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

package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.OutboundResult
import com.mustafadakhel.oag.SafeOutboundClient

import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse

enum class UrlStatus {
    REACHABLE,
    NOT_FOUND,
    SERVER_ERROR,
    BLOCKED,
    UNREACHABLE
}

data class UrlVerificationResult(
    val url: String,
    val status: UrlStatus,
    val statusCode: Int? = null
)

class UrlVerifier(
    private val client: SafeOutboundClient,
    private val allowlist: Set<String> = emptySet(),
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS
) {

    fun verify(urls: List<String>): List<UrlVerificationResult> =
        urls.mapNotNull { url -> verifyOne(url) }

    fun extractAndVerify(text: String): List<UrlVerificationResult> {
        val urls = extractUrls(text)
        return verify(urls)
    }

    private fun verifyOne(url: String): UrlVerificationResult? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        val host = uri.host ?: return null
        if (host in allowlist) return null

        val request = runCatching {
            HttpRequest.newBuilder(uri)
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .build()
        }.getOrNull() ?: return UrlVerificationResult(url, UrlStatus.UNREACHABLE)

        return when (val result = client.execute(request, HttpResponse.BodyHandlers.discarding(), timeoutMs)) {
            is OutboundResult.Blocked -> UrlVerificationResult(url, UrlStatus.BLOCKED)
            is OutboundResult.Failure -> UrlVerificationResult(url, UrlStatus.UNREACHABLE)
            is OutboundResult.Success -> {
                val code = result.value.statusCode()
                val status = when {
                    code in HTTP_SUCCESS_RANGE -> UrlStatus.REACHABLE
                    code == HTTP_NOT_FOUND -> UrlStatus.NOT_FOUND
                    code in HTTP_SERVER_ERROR_RANGE -> UrlStatus.SERVER_ERROR
                    else -> UrlStatus.REACHABLE
                }
                UrlVerificationResult(url, status, code)
            }
        }
    }

    companion object {
        private const val DEFAULT_TIMEOUT_MS = 3_000L
        private const val HTTP_NOT_FOUND = 404
        private val HTTP_SUCCESS_RANGE = 200..299
        private val HTTP_SERVER_ERROR_RANGE = 500..599
    }
}

private val URL_PATTERN = Regex(
    """https?://[^\s<>"'\]){},;]+"""
)

internal fun extractUrls(text: String): List<String> =
    URL_PATTERN.findAll(text)
        .map { it.value.trimEnd('.', ',', ')', ']', ';', ':') }
        .filter { it.length > "https://x.xx".length }
        .distinct()
        .take(MAX_URLS_PER_RESPONSE)
        .toList()

private const val MAX_URLS_PER_RESPONSE = 20
