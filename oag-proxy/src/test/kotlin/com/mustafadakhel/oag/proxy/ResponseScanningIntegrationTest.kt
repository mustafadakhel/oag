package com.mustafadakhel.oag.proxy

import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

internal class ResponseScanningIntegrationTest : ProxyHandlerTestBase() {

    @Test
    fun `response body scanning denies when response does not match expected pattern`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    val input = socket.getInputStream()
                    readHeaders(input)
                    val responseBody = """{"unexpected":"data"}"""
                    val response = "HTTP/1.1 200 OK\r\nContent-Length: ${responseBody.length}\r\n\r\n$responseBody"
                    socket.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
                    socket.getOutputStream().flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(scanPolicy("expected_token"))
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = "GET http://127.0.0.1:${upstreamServer.localPort}/v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("response_injection_detected", event.decision.reasonCode)
        }
    }

    @Test
    fun `skip_response_scanning bypasses response body scanning`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    val input = socket.getInputStream()
                    readHeaders(input)
                    val responseBody = """{"unexpected":"data"}"""
                    val response = "HTTP/1.1 200 OK\r\nContent-Length: ${responseBody.length}\r\n\r\n$responseBody"
                    socket.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
                    socket.getOutputStream().flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: deny
                allow:
                  - id: api
                    host: 127.0.0.1
                    methods: [GET]
                    paths: [/*]
                    response_body_match:
                      contains:
                        - "expected_token"
                    skip_response_scanning: true
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = "GET http://127.0.0.1:${upstreamServer.localPort}/v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            val responseText = responseOut.toString(Charsets.UTF_8)
            assertTrue(responseText.startsWith("HTTP/1.1 200 OK"), "Expected 200, got: ${responseText.take(40)}")
            val event = firstAuditEvent(auditOut)
            assertEquals("allow", event.decision.action)
        }
    }

    @Test
    fun `response body scanning passes matching response through`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    val input = socket.getInputStream()
                    readHeaders(input)
                    val responseBody = """{"data":"expected_token here"}"""
                    val response = "HTTP/1.1 200 OK\r\nContent-Length: ${responseBody.length}\r\n\r\n$responseBody"
                    socket.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
                    socket.getOutputStream().flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(scanPolicy("expected_token"))
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = "GET http://127.0.0.1:${upstreamServer.localPort}/v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            val responseText = responseOut.toString(Charsets.UTF_8)
            assertTrue(responseText.startsWith("HTTP/1.1 200 OK"), "Expected 200, got: ${responseText.take(40)}")
            assertTrue(responseText.contains("expected_token"))
            val event = firstAuditEvent(auditOut)
            assertEquals("allow", event.decision.action)
        }
    }

    private fun scanPolicy(token: String) = """
        version: 1
        defaults:
          action: deny
        allow:
          - id: api
            host: 127.0.0.1
            methods: [GET]
            paths: [/*]
            response_body_match:
              contains:
                - "$token"
    """.trimIndent()
}
