package com.mustafadakhel.oag.proxy

import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.nio.charset.Charset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

internal class UpstreamResponseErrorIntegrationTest : ProxyHandlerTestBase() {

    companion object {
        @JvmStatic
        fun malformedResponses() = listOf(
            arrayOf("overlong header line", "a".repeat(9000).let { "HTTP/1.1 200 OK\r\nX-Long: $it\r\n\r\n" }, Charsets.US_ASCII),
            arrayOf("malformed header line", "HTTP/1.1 200 OK\r\nMalformedHeader\r\n\r\n", Charsets.US_ASCII),
            arrayOf("leading whitespace header", "HTTP/1.1 200 OK\r\n X-Test: value\r\n\r\n", Charsets.US_ASCII),
            arrayOf("invalid header name token", "HTTP/1.1 200 OK\r\nBad Header: value\r\n\r\n", Charsets.US_ASCII),
            arrayOf("control character in header value", "HTTP/1.1 200 OK\r\nX-Test: ok\u0001bad\r\n\r\n", Charsets.US_ASCII),
            arrayOf("DEL character in header value", "HTTP/1.1 200 OK\r\nX-Test: ok\u007Fbad\r\n\r\n", Charsets.US_ASCII),
            arrayOf("non ascii header value", "HTTP/1.1 200 OK\r\nX-Test: caf\u00E9\r\n\r\n", Charsets.ISO_8859_1),
            arrayOf("malformed status line", "NOT_HTTP\r\nContent-Length: 0\r\n\r\n", Charsets.US_ASCII),
            arrayOf("unsupported transfer encoding", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\npayload", Charsets.US_ASCII),
            arrayOf("non final chunked transfer encoding", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n2\r\nOK\r\n0\r\n\r\n", Charsets.US_ASCII),
            arrayOf("out of range status code", "HTTP/1.1 700 Invalid\r\nContent-Length: 0\r\n\r\n", Charsets.US_ASCII),
            arrayOf("duplicate content length", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nOK", Charsets.US_ASCII),
            arrayOf("conflicting framing headers", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n", Charsets.US_ASCII),
        )

        @JvmStatic
        fun invalidContentLengthResponses() = listOf(
            arrayOf("invalid content length", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"),
            arrayOf("non numeric content length", "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n"),
            arrayOf("overflow content length", "HTTP/1.1 200 OK\r\nContent-Length: 999999999999999999999\r\n\r\n"),
        )
    }

    @Test
    fun `http upstream connection failure returns 502 and audits deny`() = runTest {
        val closedPort = ServerSocket(0).use { it.localPort }
        val policyPath = writePolicy(allowLocalPolicy())
        val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

        val request = getRequest(closedPort)
        val responseOut = ByteArrayOutputStream()
        handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

        assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 502 Bad Gateway"))
        assertUpstreamDenyAudit(auditOut)
    }

    @ParameterizedTest(name = "upstream {0} returns 502")
    @MethodSource("malformedResponses")
    fun `http upstream malformed response returns 502 and audits deny`(
        description: String,
        responsePayload: String,
        charset: Charset
    ) = runTest {
        assertUpstreamResponseReturns502(responsePayload, charset)
    }

    @ParameterizedTest(name = "upstream {0} returns 502")
    @MethodSource("invalidContentLengthResponses")
    fun `http upstream invalid content-length returns 502 and audits deny`(
        description: String,
        responsePayload: String
    ) = runTest {
        assertUpstreamResponseReturns502WithFinally(responsePayload)
    }

    @Test
    fun `http upstream closes before status line returns 502 and audits deny`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(getRequest(upstreamServer.localPort).toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 502 Bad Gateway"))
            assertUpstreamDenyAudit(auditOut)
        }
    }

    @Test
    fun `http upstream response with truncated fixed length body audits deny without appending fallback 502`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nOK".toByteArray(Charsets.US_ASCII))
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
            assertUpstreamDenyAudit(auditOut)
        }
    }

    private suspend fun assertUpstreamResponseReturns502(responsePayload: String, charset: Charset = Charsets.US_ASCII) {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write(responsePayload.toByteArray(charset))
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(getRequest(upstreamServer.localPort).toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 502 Bad Gateway"))
            assertUpstreamDenyAudit(auditOut)
        }
    }

    private suspend fun assertUpstreamResponseReturns502WithFinally(responsePayload: String) {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                try {
                    upstreamServer.accept().use { socket ->
                        readHeaders(socket.getInputStream())
                        val output = socket.getOutputStream()
                        output.write(responsePayload.toByteArray(Charsets.US_ASCII))
                        output.flush()
                    }
                } finally {
                    served.countDown()
                }
            }

            val policyPath = writePolicy(allowLocalPolicy())
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(getRequest(upstreamServer.localPort).toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 502 Bad Gateway"))
            assertUpstreamDenyAudit(auditOut)
        }
    }

    private fun assertUpstreamDenyAudit(auditOut: ByteArrayOutputStream) {
        val event = firstAuditEvent(auditOut)
        assertEquals("deny", event.decision.action)
        assertEquals("upstream_connection_failed", event.decision.reasonCode)
    }

    private fun allowLocalPolicy() = """
        version: 1
        defaults:
          action: DENY
        allow:
          - id: local-http
            host: 127.0.0.1
            methods: [GET]
            paths: [/v1/*]
    """.trimIndent()

    private fun getRequest(port: Int) = """
        GET http://127.0.0.1:$port/v1/models HTTP/1.1
        Host: ignored
        Content-Length: 0


    """.trimIndent().replace("\n", "\r\n")
}
