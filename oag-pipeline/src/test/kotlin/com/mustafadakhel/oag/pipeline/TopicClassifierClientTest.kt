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

import com.mustafadakhel.oag.SafeOutboundClient

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TopicClassifierClientTest {

    @Test
    fun `successful classification returns correct topic and confidence`() {
        val mockClient = TopicClassifierClient { request ->
            assertEquals("test text", request.text)
            assertTrue(request.topics.contains("finance"))
            TopicClassificationResponse(topic = "finance", confidence = 0.95)
        }
        val result = mockClient.classify(TopicClassificationRequest("test text", listOf("finance", "health")))
        assertEquals("finance", result.topic)
        assertEquals(0.95, result.confidence, 0.001)
    }

    @Test
    fun `SSRF URL rejected at construction`() {
        val client = SafeOutboundClient()
        assertFailsWith<IllegalArgumentException> {
            ExternalTopicClassifierClient(
                client = client,
                endpointUrl = "http://127.0.0.1:8080/classify",
                timeoutMs = 1000
            )
        }
    }

    @Test
    fun `TopicClassificationRequest serializes correctly`() {
        val request = TopicClassificationRequest("hello", listOf("a", "b"))
        assertEquals("hello", request.text)
        assertEquals(listOf("a", "b"), request.topics)
    }

    @Test
    fun `TopicClassificationResponse holds topic and confidence`() {
        val response = TopicClassificationResponse(topic = null, confidence = 0.3)
        assertEquals(null, response.topic)
        assertEquals(0.3, response.confidence, 0.001)
    }

    @Test
    fun `TopicClassificationException carries message`() {
        val ex = TopicClassificationException("test error")
        assertEquals("test error", ex.message)
    }

    @Test
    fun `TopicClassificationException carries cause`() {
        val cause = RuntimeException("root")
        val ex = TopicClassificationException("wrapper", cause)
        assertEquals("wrapper", ex.message)
        assertNotNull(ex.cause)
    }

    @Test
    fun `client interface is a fun interface`() {
        // Verify TopicClassifierClient can be implemented as a lambda
        val client: TopicClassifierClient = TopicClassifierClient {
            TopicClassificationResponse(topic = "test", confidence = 1.0)
        }
        val result = client.classify(TopicClassificationRequest("x", listOf("test")))
        assertEquals("test", result.topic)
    }
}
