package com.mustafadakhel.oag.proxy

import kotlin.concurrent.thread
import kotlin.system.measureTimeMillis
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

internal class ResponseFramingIntegrationTest : ProxyHandlerTestBase() {

    @Test
    fun `http response with content length does not wait for upstream close`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".toByteArray(Charsets.US_ASCII))
                    output.flush()
                    Thread.sleep(400)
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, _) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                readTimeoutMs = 2_000
            )

            val responseOut = ByteArrayOutputStream()
            val elapsedMs = measureTimeMillis {
                handler.handle(ByteArrayInputStream(getRequest(upstreamServer.localPort).toByteArray(Charsets.US_ASCII)), responseOut)
            }

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertTrue(elapsedMs < 300, "expected response relay to finish promptly, took ${elapsedMs}ms")
            assertTrue(served.await(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `http chunked response does not wait for upstream close`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write(
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n"
                            .toByteArray(Charsets.US_ASCII)
                    )
                    output.flush()
                    Thread.sleep(400)
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, _) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                readTimeoutMs = 2_000
            )

            val responseOut = ByteArrayOutputStream()
            val elapsedMs = measureTimeMillis {
                handler.handle(ByteArrayInputStream(getRequest(upstreamServer.localPort).toByteArray(Charsets.US_ASCII)), responseOut)
            }

            val response = responseOut.toString(Charsets.UTF_8)
            assertTrue(response.startsWith("HTTP/1.1 200 OK"))
            assertTrue(response.contains("2\r\nOK\r\n0\r\n\r\n"))
            assertTrue(elapsedMs < 300, "expected chunked relay to finish promptly, took ${elapsedMs}ms")
            assertTrue(served.await(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `http unframed response read timeout audits deny without appending fallback 502`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write("HTTP/1.1 200 OK\r\n\r\nOK".toByteArray(Charsets.US_ASCII))
                    output.flush()
                    Thread.sleep(400)
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, auditOut) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                readTimeoutMs = 150
            )

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(getRequest(upstreamServer.localPort).toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            val response = responseOut.toString(Charsets.UTF_8)
            assertTrue(response.startsWith("HTTP/1.1 200 OK"))
            assertFalse(response.contains("HTTP/1.1 502 Bad Gateway"))
            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("upstream_connection_failed", event.decision.reasonCode)
        }
    }

    @Test
    fun `head response with content length does not wait for upstream close`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    output.flush()
                    Thread.sleep(400)
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy(method = "HEAD"))
            val (handler, _) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                readTimeoutMs = 2_000
            )

            val request = """
                HEAD http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            val elapsedMs = measureTimeMillis {
                handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)
            }

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertTrue(elapsedMs < 300, "expected HEAD relay to finish promptly, took ${elapsedMs}ms")
            assertTrue(served.await(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `status 204 response with content length does not wait for upstream close`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    output.flush()
                    Thread.sleep(400)
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, _) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                readTimeoutMs = 2_000
            )

            val responseOut = ByteArrayOutputStream()
            val elapsedMs = measureTimeMillis {
                handler.handle(ByteArrayInputStream(getRequest(upstreamServer.localPort).toByteArray(Charsets.US_ASCII)), responseOut)
            }

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 204 No Content"))
            assertTrue(elapsedMs < 300, "expected 204 relay to finish promptly, took ${elapsedMs}ms")
            assertTrue(served.await(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `http upstream response with malformed chunk trailer audits deny without appending fallback 502`() = runTest {
        assertChunkedResponseAuditsDeny(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\nBadTrailer\r\n\r\n"
        )
    }

    @Test
    fun `http upstream response with signed chunk size audits deny without appending fallback 502`() = runTest {
        assertChunkedResponseAuditsDeny(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+2\r\nOK\r\n0\r\n\r\n"
        )
    }

    @Test
    fun `http chunked response with zero length only chunk relays empty body`() = runTest {
        assertChunkedResponseAllowed(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ) { response ->
            assertTrue(response.contains("0\r\n\r\n"))
        }
    }

    @Test
    fun `http chunked response with chunk extensions relays correctly`() = runTest {
        assertChunkedResponseAllowed(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=val\r\nOK\r\n0\r\n\r\n"
        ) { response ->
            assertTrue(response.contains("OK"))
        }
    }

    @Test
    fun `http chunked response with valid trailers relays correctly`() = runTest {
        assertChunkedResponseAllowed(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\nX-Checksum: abc123\r\n\r\n"
        ) { response ->
            assertTrue(response.contains("Hello"))
            assertTrue(response.contains("X-Checksum: abc123"))
        }
    }

    @Test
    fun `http chunked response with multiple data chunks relays all data`() = runTest {
        assertChunkedResponseAllowed(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n"
        ) { response ->
            assertTrue(response.contains("Hello"))
            assertTrue(response.contains(" World"))
        }
    }

    @Test
    fun `http chunked response with oversized chunk returns 502`() = runTest {
        val oversizedChunkHex = "4000001"
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write(
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n$oversizedChunkHex\r\n"
                            .toByteArray(Charsets.US_ASCII)
                    )
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(getRequest(upstreamServer.localPort).toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("upstream_connection_failed", event.decision.reasonCode)
        }
    }

    @Test
    fun `http chunked response with uppercase hex chunk size relays correctly`() = runTest {
        val chunkData = "0123456789"
        val chunkSizeHex = Integer.toHexString(chunkData.length).uppercase()
        assertChunkedResponseAllowed(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n$chunkSizeHex\r\n$chunkData\r\n0\r\n\r\n"
        ) { response ->
            assertTrue(response.contains("0123456789"))
        }
    }

    private suspend fun assertChunkedResponseAuditsDeny(responsePayload: String) {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write(responsePayload.toByteArray(Charsets.US_ASCII))
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(getRequest(upstreamServer.localPort).toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertFalse(responseOut.toString(Charsets.UTF_8).contains("HTTP/1.1 502 Bad Gateway"))
            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("upstream_connection_failed", event.decision.reasonCode)
        }
    }

    private suspend fun assertChunkedResponseAllowed(responsePayload: String, assertions: (String) -> Unit = {}) {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write(responsePayload.toByteArray(Charsets.US_ASCII))
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = getRequest(upstreamServer.localPort)
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            val response = responseOut.toString(Charsets.UTF_8)
            assertTrue(response.startsWith("HTTP/1.1 200 OK"))
            assertions(response)
            val event = firstAuditEvent(auditOut)
            assertEquals("allow", event.decision.action)
        }
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

    private fun getRequest(port: Int) = """
        GET http://127.0.0.1:$port/v1/models HTTP/1.1
        Host: ignored
        Content-Length: 0


    """.trimIndent().replace("\n", "\r\n")
}
