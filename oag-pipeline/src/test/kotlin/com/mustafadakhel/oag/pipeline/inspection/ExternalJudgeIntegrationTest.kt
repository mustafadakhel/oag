package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.SafeOutboundClient
import com.mustafadakhel.oag.http.HttpConstants
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer

import java.net.InetSocketAddress

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ExternalJudgeIntegrationTest {

    private val servers = mutableListOf<HttpServer>()

    @AfterTest
    fun tearDown() {
        servers.forEach { it.stop(0) }
    }

    private fun startServer(handler: (HttpExchange) -> Unit): HttpServer {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/judge", handler)
        server.start()
        servers.add(server)
        return server
    }

    private fun clientFor(port: Int, signingSecret: String? = null): ExternalJudgeClient {
        val safeClient = SafeOutboundClient(skipSsrfCheck = true)
        return ExternalJudgeClient(
            client = safeClient,
            endpointUrl = "http://127.0.0.1:$port/judge",
            timeoutMs = 5000,
            signingSecret = signingSecret
        )
    }

    @Test
    fun `successful judge call returns parsed score and decision`() {
        val server = startServer { exchange ->
            val body = """{"score":0.85,"decision":"deny","reason":"suspicious content"}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val client = clientFor(server.address.port)
        val result = client.invoke(JudgeRequest(requestBody = "test body"))
        assertEquals(0.85, result.score, 0.001)
        assertEquals(JudgeDecision.DENY, result.decision)
        assertEquals("suspicious content", result.reason)
        assertNull(result.error)
        assertTrue(result.latencyMs >= 0)
    }

    @Test
    fun `HMAC signature sent when signingSecret configured`() {
        var receivedSignature: String? = null
        val server = startServer { exchange ->
            receivedSignature = exchange.requestHeaders.getFirst(HttpConstants.OAG_SIGNATURE)
            val body = """{"score":0.1}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val client = clientFor(server.address.port, signingSecret = "my-secret")
        client.invoke(JudgeRequest(requestBody = "body"))
        assertNotNull(receivedSignature)
        assertTrue(receivedSignature!!.startsWith("sha256="))
    }

    @Test
    fun `HTTP 500 returns ABSTAIN with error`() {
        val server = startServer { exchange ->
            exchange.sendResponseHeaders(500, 0)
            exchange.close()
        }
        val client = clientFor(server.address.port)
        val result = client.invoke(JudgeRequest(requestBody = "body"))
        assertEquals(JudgeDecision.ABSTAIN, result.decision)
        assertNotNull(result.error)
        assertTrue("500" in result.error!!)
    }

    @Test
    fun `invalid JSON response returns ABSTAIN with error`() {
        val server = startServer { exchange ->
            val body = "not json"
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val client = clientFor(server.address.port)
        val result = client.invoke(JudgeRequest(requestBody = "body"))
        assertEquals(JudgeDecision.ABSTAIN, result.decision)
        assertNotNull(result.error)
    }

    @Test
    fun `oversized response returns ABSTAIN with error`() {
        val server = startServer { exchange ->
            val body = "x".repeat(70_000)
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val client = clientFor(server.address.port)
        val result = client.invoke(JudgeRequest(requestBody = "body"))
        assertEquals(JudgeDecision.ABSTAIN, result.decision)
        assertNotNull(result.error)
        assertTrue("65536" in result.error!!)
    }

    @Test
    fun `SSRF rejection for private IP at execute time`() {
        // Use skipSsrfCheck=false (default) and validateUrl=false to bypass init check
        // but the execute() call still validates
        val client = SafeOutboundClient()
        val judgeClient = ExternalJudgeClient(
            client = client,
            endpointUrl = "http://192.168.1.1/judge",
            validateUrl = false
        )
        val result = judgeClient.invoke(JudgeRequest(requestBody = "body"))
        assertEquals(JudgeDecision.ABSTAIN, result.decision)
        assertNotNull(result.error)
        assertTrue("blocked" in result.error!!)
    }
}
