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

package com.mustafadakhel.oag.policy.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyTopicClassification(
    val enabled: Boolean? = null,
    @SerialName("denied_topics") val deniedTopics: List<String>? = null,
    @SerialName("allowed_topics") val allowedTopics: List<String>? = null,
    @SerialName("confidence_threshold") val confidenceThreshold: Double? = null,
    @SerialName("endpoint_url") val endpointUrl: String? = null,
    @SerialName("endpoint_timeout_ms") val endpointTimeoutMs: Int? = null,
    @SerialName("signing_secret") val signingSecret: String? = null,
    @SerialName("on_error") val onError: String? = null,
    @SerialName("max_text_bytes") val maxTextBytes: Int? = null
)
