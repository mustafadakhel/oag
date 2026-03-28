package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.SafeOutboundClient
import com.mustafadakhel.oag.http.HttpConstants
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer

import java.net.InetSocketAddress

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TopicClassifierClientTest {

    private val servers = mutableListOf<HttpServer>()

    @AfterTest
    fun tearDown() {
        servers.forEach { it.stop(0) }
    }

    private fun startServer(handler: (HttpExchange) -> Unit): HttpServer {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/classify", handler)
        server.start()
        servers.add(server)
        return server
    }

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
        val client: TopicClassifierClient = TopicClassifierClient {
            TopicClassificationResponse(topic = "test", confidence = 1.0)
        }
        val result = client.classify(TopicClassificationRequest("x", listOf("test")))
        assertEquals("test", result.topic)
    }

    @Test
    fun `HMAC signature header present when signingSecret set`() {
        var receivedSignature: String? = null
        val server = startServer { exchange ->
            receivedSignature = exchange.requestHeaders.getFirst(HttpConstants.OAG_SIGNATURE)
            val body = """{"topic":"finance","confidence":0.9}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val port = server.address.port
        val safeClient = SafeOutboundClient(skipSsrfCheck = true)
        val client = ExternalTopicClassifierClient(
            client = safeClient,
            endpointUrl = "http://127.0.0.1:$port/classify",
            timeoutMs = 5000,
            signingSecret = "test-secret",
            validateUrl = false
        )
        client.classify(TopicClassificationRequest("hello", listOf("finance")))
        assertNotNull(receivedSignature, "OAG-Signature header should be present")
        assertTrue(receivedSignature!!.startsWith("sha256="))
    }

    @Test
    fun `timeout enforcement triggers TopicClassificationException`() {
        val server = startServer { exchange ->
            Thread.sleep(3000)
            exchange.sendResponseHeaders(200, 0)
            exchange.close()
        }
        val port = server.address.port
        val safeClient = SafeOutboundClient(skipSsrfCheck = true)
        val client = ExternalTopicClassifierClient(
            client = safeClient,
            endpointUrl = "http://127.0.0.1:$port/classify",
            timeoutMs = 500,
            validateUrl = false
        )
        assertFailsWith<TopicClassificationException> {
            client.classify(TopicClassificationRequest("hello", listOf("test")))
        }
    }

    @Test
    fun `response over 64KB rejected with TopicClassificationException`() {
        val server = startServer { exchange ->
            val body = "x".repeat(70_000)
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val port = server.address.port
        val safeClient = SafeOutboundClient(skipSsrfCheck = true)
        val client = ExternalTopicClassifierClient(
            client = safeClient,
            endpointUrl = "http://127.0.0.1:$port/classify",
            timeoutMs = 5000,
            validateUrl = false
        )
        assertFailsWith<TopicClassificationException> {
            client.classify(TopicClassificationRequest("hello", listOf("test")))
        }
    }

    @Test
    fun `non-JSON response throws TopicClassificationException`() {
        val server = startServer { exchange ->
            val body = "this is not json"
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val port = server.address.port
        val safeClient = SafeOutboundClient(skipSsrfCheck = true)
        val client = ExternalTopicClassifierClient(
            client = safeClient,
            endpointUrl = "http://127.0.0.1:$port/classify",
            timeoutMs = 5000,
            validateUrl = false
        )
        assertFailsWith<TopicClassificationException> {
            client.classify(TopicClassificationRequest("hello", listOf("test")))
        }
    }

    @Test
    fun `HTTP 500 response throws TopicClassificationException`() {
        val server = startServer { exchange ->
            exchange.sendResponseHeaders(500, 0)
            exchange.close()
        }
        val port = server.address.port
        val safeClient = SafeOutboundClient(skipSsrfCheck = true)
        val client = ExternalTopicClassifierClient(
            client = safeClient,
            endpointUrl = "http://127.0.0.1:$port/classify",
            timeoutMs = 5000,
            validateUrl = false
        )
        assertFailsWith<TopicClassificationException> {
            client.classify(TopicClassificationRequest("hello", listOf("test")))
        }
    }

    @Test
    fun `wrong JSON schema throws TopicClassificationException`() {
        val server = startServer { exchange ->
            val body = """{"wrong_field":"value"}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val port = server.address.port
        val safeClient = SafeOutboundClient(skipSsrfCheck = true)
        val client = ExternalTopicClassifierClient(
            client = safeClient,
            endpointUrl = "http://127.0.0.1:$port/classify",
            timeoutMs = 5000,
            validateUrl = false
        )
        assertFailsWith<TopicClassificationException> {
            client.classify(TopicClassificationRequest("hello", listOf("test")))
        }
    }
}
