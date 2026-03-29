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

package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.OutboundResult
import com.mustafadakhel.oag.SafeOutboundClient
import com.mustafadakhel.oag.computeHmacSha256
import com.mustafadakhel.oag.http.HttpConstants

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse

fun interface TopicClassifierClient {
    fun classify(request: TopicClassificationRequest): TopicClassificationResponse
}

class TopicClassificationException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

@Serializable
data class TopicClassificationRequest(
    val text: String,
    val topics: List<String>
)

@Serializable
data class TopicClassificationResponse(
    val topic: String?,
    val confidence: Double
)

class ExternalTopicClassifierClient(
    private val client: SafeOutboundClient,
    private val endpointUrl: String,
    private val timeoutMs: Long,
    private val signingSecret: String? = null,
    private val maxResponseBytes: Int = DEFAULT_MAX_RESPONSE_BYTES
) : TopicClassifierClient {

    private val endpointUri = URI(endpointUrl)
    private val responseJson = Json { ignoreUnknownKeys = true }

    init {
        val validation = client.validateTarget(endpointUri)
        require(validation is OutboundResult.Success) {
            "Topic classification endpoint is not reachable: $endpointUrl"
        }
    }

    override fun classify(request: TopicClassificationRequest): TopicClassificationResponse {
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
        val result = client.execute(httpRequest, HttpResponse.BodyHandlers.ofInputStream(), timeoutMs)

        return when (result) {
            is OutboundResult.Blocked ->
                throw TopicClassificationException("Endpoint blocked: ${result.reason}")
            is OutboundResult.Failure ->
                throw TopicClassificationException("Endpoint request failed: ${result.error.message}", result.error)
            is OutboundResult.Success -> {
                val response = result.value
                if (response.statusCode() !in 200..299) {
                    throw TopicClassificationException("Endpoint returned HTTP ${response.statusCode()}")
                }
                val bytes = response.body().readNBytes(maxResponseBytes + 1)
                if (bytes.size > maxResponseBytes) {
                    throw TopicClassificationException("Response exceeds max size of $maxResponseBytes bytes")
                }
                val responseText = String(bytes, Charsets.UTF_8)
                runCatching {
                    responseJson.decodeFromString<TopicClassificationResponse>(responseText)
                }.getOrElse {
                    throw TopicClassificationException("Invalid response JSON: ${it.message}", it)
                }
            }
        }
    }

    companion object {
        private const val DEFAULT_MAX_RESPONSE_BYTES = 65_536
    }
}
