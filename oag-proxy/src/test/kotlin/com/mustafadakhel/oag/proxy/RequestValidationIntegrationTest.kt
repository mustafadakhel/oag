package com.mustafadakhel.oag.proxy

import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

internal class RequestValidationIntegrationTest : ProxyHandlerTestBase() {

    @Test
    fun `http deny on body too large blocks upstream and audits deny`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val connected = AtomicBoolean(false)
            val acceptDone = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.soTimeout = 300
                try {
                    upstreamServer.accept().use {
                        connected.set(true)
                    }
                } catch (_: SocketTimeoutException) {
                    connected.set(false)
                } finally {
                    acceptDone.countDown()
                }
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: DENY
                allow:
                  - id: local-http
                    host: 127.0.0.1
                    methods: [POST]
                    paths: [/v1/*]
                    max_body_bytes: 5
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = """
                POST http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 10

                0123456789
            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))
            assertTrue(acceptDone.await(5, TimeUnit.SECONDS))
            assertFalse(connected.get())

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("body_too_large", event.decision.reasonCode)
        }
    }

    @Test
    fun `http chunked request body is rejected as invalid request`() = runTest {
        assertInvalidRequest(
            """
            POST http://127.0.0.1:PORT/v1/models HTTP/1.1
            Host: ignored
            Transfer-Encoding: chunked

            5
            hello
            0


            """.trimIndent()
        )
    }

    @Test
    fun `http request with transfer encoding header is rejected as invalid request`() = runTest {
        assertInvalidRequest(
            """
            POST http://127.0.0.1:PORT/v1/models HTTP/1.1
            Host: ignored
            Transfer-Encoding: gzip

            payload
            """.trimIndent()
        )
    }

    @Test
    fun `http request with conflicting framing headers is rejected as invalid request`() = runTest {
        assertInvalidRequest(
            """
            POST http://127.0.0.1:PORT/v1/models HTTP/1.1
            Host: ignored
            Content-Length: 5
            Transfer-Encoding: chunked

            hello
            """.trimIndent()
        )
    }

    @Test
    fun `http request with duplicate host header is rejected as invalid request`() = runTest {
        assertInvalidRequest(
            """
            GET http://127.0.0.1:PORT/v1/models HTTP/1.1
            Host: ignored
            Host: duplicate
            Content-Length: 0


            """.trimIndent(),
            method = "GET"
        )
    }

    @Test
    fun `http request with truncated fixed length body returns 400 and audits invalid request`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy(method = "POST"))
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = """
                POST http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 5

                hi
            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 400 Bad Request"))
            assertInvalidRequestAudit(auditOut)
        }
    }

    @Test
    fun `http request body read timeout returns 400 and audits invalid request`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy(method = "POST"))
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = """
                POST http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 5

                hi
            """.trimIndent().replace("\n", "\r\n")

            val clientInput = TimeoutAfterBufferInputStream(request.toByteArray(Charsets.US_ASCII))
            val responseOut = ByteArrayOutputStream()
            handler.handle(clientInput, responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 400 Bad Request"))
            assertInvalidRequestAudit(auditOut)
        }
    }

    @Test
    fun `http request body read io failure returns 400 and audits invalid request`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy(method = "POST"))
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = """
                POST http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 5

                hi
            """.trimIndent().replace("\n", "\r\n")

            val clientInput = IoFailureAfterBufferInputStream(request.toByteArray(Charsets.US_ASCII))
            val responseOut = ByteArrayOutputStream()
            handler.handle(clientInput, responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 400 Bad Request"))
            assertInvalidRequestAudit(auditOut)
        }
    }

    @Test
    fun `http11 request without host header is rejected as invalid request`() = runTest {
        assertInvalidRequest(
            """
            GET http://127.0.0.1:PORT/v1/models HTTP/1.1
            Content-Length: 0


            """.trimIndent(),
            method = "GET"
        )
    }

    private suspend fun assertInvalidRequest(requestTemplate: String, method: String = "POST") {
        ServerSocket(0).use { upstreamServer ->
            val connected = AtomicBoolean(false)
            val acceptDone = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.soTimeout = 300
                try {
                    upstreamServer.accept().use {
                        connected.set(true)
                    }
                } catch (_: SocketTimeoutException) {
                    connected.set(false)
                } finally {
                    acceptDone.countDown()
                }
            }

            val policyPath = writePolicy(allowLocalPolicy(method = method))
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = requestTemplate.replace("PORT", upstreamServer.localPort.toString()).replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 400 Bad Request"))
            assertTrue(acceptDone.await(5, TimeUnit.SECONDS))
            assertFalse(connected.get())

            assertInvalidRequestAudit(auditOut)
        }
    }

    private fun assertInvalidRequestAudit(auditOut: ByteArrayOutputStream) {
        val event = firstAuditEvent(auditOut)
        assertEquals("deny", event.decision.action)
        assertEquals("invalid_request", event.decision.reasonCode)
    }

    private fun allowLocalPolicy(method: String = "GET") = """
        version: 1
        defaults:
          action: DENY
        allow:
          - id: local-http
            host: 127.0.0.1
            methods: [$method]
            paths: [/v1/*]
    """.trimIndent()
}
