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

package com.mustafadakhel.oag.pipeline.inspection

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class JudgeRequest(
    @SerialName("request_body") val requestBody: String,
    @SerialName("response_body") val responseBody: String? = null,
    @SerialName("injection_score") val injectionScore: Double? = null,
    val host: String? = null,
    val path: String? = null,
    val method: String? = null
)

@Serializable
data class JudgeResponse(
    val score: Double,
    val decision: String? = null,
    val reason: String? = null
)

enum class JudgeDecision {
    DENY,
    ALLOW,
    ABSTAIN;

    companion object {
        fun fromLabel(label: String?): JudgeDecision = when (label?.lowercase()) {
            "deny" -> DENY
            "allow" -> ALLOW
            else -> ABSTAIN
        }
    }
}

data class JudgeResult(
    val score: Double,
    val decision: JudgeDecision,
    val source: String,
    val latencyMs: Long,
    val reason: String? = null,
    val error: String? = null
)

fun String.sanitizeForJudge(maxLength: Int = MAX_JUDGE_BODY_LENGTH): String =
    take(maxLength).replace("\u0000", "")

private const val MAX_JUDGE_BODY_LENGTH = 32_768
