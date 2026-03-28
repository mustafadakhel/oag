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

package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicyTopicClassification

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TopicClassificationValidatorTest {

    private fun validate(config: PolicyTopicClassification) =
        config.validate("test")

    @Test
    fun `enabled without endpoint_url fails`() {
        val errors = validate(PolicyTopicClassification(enabled = true, deniedTopics = listOf("violence")))
        assertTrue(errors.any { "endpoint_url" in it.path && "Must be set" in it.message })
    }

    @Test
    fun `invalid URL scheme fails`() {
        val errors = validate(PolicyTopicClassification(
            enabled = true,
            endpointUrl = "ftp://example.com/classify",
            deniedTopics = listOf("violence")
        ))
        assertTrue(errors.any { "endpoint_url" in it.path && "http or https" in it.message })
    }

    @Test
    fun `http scheme produces insecurity warning`() {
        val errors = validate(PolicyTopicClassification(
            enabled = true,
            endpointUrl = "http://example.com/classify",
            deniedTopics = listOf("violence")
        ))
        assertTrue(errors.any { "endpoint_url" in it.path && "insecure" in it.message })
    }

    @Test
    fun `URL with userinfo fails`() {
        val errors = validate(PolicyTopicClassification(
            enabled = true,
            endpointUrl = "https://user:pass@example.com/classify",
            deniedTopics = listOf("violence")
        ))
        assertTrue(errors.any { "endpoint_url" in it.path && "userinfo" in it.message })
    }

    @Test
    fun `both denied_topics and allowed_topics set fails`() {
        val errors = validate(PolicyTopicClassification(
            enabled = true,
            endpointUrl = "https://example.com/classify",
            deniedTopics = listOf("violence"),
            allowedTopics = listOf("finance")
        ))
        assertTrue(errors.any { "Cannot set both" in it.message })
    }

    @Test
    fun `enabled with empty topic lists fails`() {
        val errors = validate(PolicyTopicClassification(
            enabled = true,
            endpointUrl = "https://example.com/classify"
        ))
        assertTrue(errors.any { "non-empty" in it.message })
    }

    @Test
    fun `confidence threshold 0_0 fails`() {
        val errors = validate(PolicyTopicClassification(confidenceThreshold = 0.0))
        assertTrue(errors.any { "confidence_threshold" in it.path })
    }

    @Test
    fun `confidence threshold 1_1 fails`() {
        val errors = validate(PolicyTopicClassification(confidenceThreshold = 1.1))
        assertTrue(errors.any { "confidence_threshold" in it.path })
    }

    @Test
    fun `confidence threshold 1_0 passes`() {
        val errors = validate(PolicyTopicClassification(confidenceThreshold = 1.0))
        assertTrue(errors.none { "confidence_threshold" in it.path })
    }

    @Test
    fun `timeout 0 fails`() {
        val errors = validate(PolicyTopicClassification(endpointTimeoutMs = 0))
        assertTrue(errors.any { "endpoint_timeout_ms" in it.path })
    }

    @Test
    fun `timeout 11000 fails`() {
        val errors = validate(PolicyTopicClassification(endpointTimeoutMs = 11000))
        assertTrue(errors.any { "endpoint_timeout_ms" in it.path })
    }

    @Test
    fun `timeout 2000 passes`() {
        val errors = validate(PolicyTopicClassification(endpointTimeoutMs = 2000))
        assertTrue(errors.none { "endpoint_timeout_ms" in it.path })
    }

    @Test
    fun `invalid onError fails`() {
        val errors = validate(PolicyTopicClassification(onError = "retry"))
        assertTrue(errors.any { "on_error" in it.path })
    }

    @Test
    fun `onError deny passes`() {
        val errors = validate(PolicyTopicClassification(onError = "deny"))
        assertTrue(errors.none { "on_error" in it.path })
    }

    @Test
    fun `onError allow passes`() {
        val errors = validate(PolicyTopicClassification(onError = "allow"))
        assertTrue(errors.none { "on_error" in it.path })
    }

    @Test
    fun `control chars in topic label fails`() {
        val errors = validate(PolicyTopicClassification(deniedTopics = listOf("viol\u0001ence")))
        assertTrue(errors.any { "control characters" in it.message })
    }

    @Test
    fun `topic label over 256 chars fails`() {
        val errors = validate(PolicyTopicClassification(deniedTopics = listOf("a".repeat(257))))
        assertTrue(errors.any { "256" in it.message })
    }

    @Test
    fun `blank topic label fails`() {
        val errors = validate(PolicyTopicClassification(deniedTopics = listOf("  ")))
        assertTrue(errors.any { "blank" in it.message.lowercase() })
    }

    @Test
    fun `fully valid config produces no errors`() {
        val errors = validate(PolicyTopicClassification(
            enabled = true,
            endpointUrl = "https://classifier.example.com/api/classify",
            deniedTopics = listOf("violence", "illegal_activity"),
            confidenceThreshold = 0.8,
            endpointTimeoutMs = 3000,
            onError = "deny",
            maxTextBytes = 4096
        ))
        assertEquals(emptyList(), errors)
    }
}
