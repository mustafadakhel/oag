package com.mustafadakhel.oag.proxy

import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

internal class HeaderRewriteIntegrationTest : ProxyHandlerTestBase() {

    @Test
    fun `http header rewrite SET adds header to upstream request`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val upstreamRequest = AtomicReference("")
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    val input = socket.getInputStream()
                    val output = socket.getOutputStream()
                    upstreamRequest.set(readHeaders(input))
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".toByteArray(Charsets.US_ASCII))
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: DENY
                allow:
                  - id: local
                    host: 127.0.0.1
                    methods: [GET]
                    paths: [/*]
                    header_rewrites:
                      - action: SET
                        header: X-Injected
                        value: from-oag
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = "GET http://127.0.0.1:${upstreamServer.localPort}/v1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertTrue(upstreamRequest.get().contains("X-Injected: from-oag"), "Upstream should receive SET header")

            val event = firstAuditEvent(auditOut)
            assertEquals("allow", event.decision.action)
            val rewrites = event.headerRewrites
            assertNotNull(rewrites)
            assertEquals(1, rewrites.size)
            assertEquals("set", rewrites[0].action)
            assertEquals("X-Injected", rewrites[0].header)
        }
    }

    @Test
    fun `http header rewrite REMOVE strips header from upstream request`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val upstreamRequest = AtomicReference("")
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    val input = socket.getInputStream()
                    val output = socket.getOutputStream()
                    upstreamRequest.set(readHeaders(input))
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".toByteArray(Charsets.US_ASCII))
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: DENY
                allow:
                  - id: local
                    host: 127.0.0.1
                    methods: [GET]
                    paths: [/*]
                    header_rewrites:
                      - action: REMOVE
                        header: X-Secret-Internal
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = "GET http://127.0.0.1:${upstreamServer.localPort}/v1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Secret-Internal: leak\r\nContent-Length: 0\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertFalse(upstreamRequest.get().contains("X-Secret-Internal"), "Upstream should NOT receive REMOVED header")
            assertFalse(upstreamRequest.get().contains("leak"), "Upstream should NOT receive removed header value")

            val event = firstAuditEvent(auditOut)
            val rewrites = event.headerRewrites
            assertNotNull(rewrites)
            assertEquals(1, rewrites.size)
            assertEquals("remove", rewrites[0].action)
        }
    }

    @Test
    fun `http header rewrite APPEND appends to existing header in upstream request`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val upstreamRequest = AtomicReference("")
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    val input = socket.getInputStream()
                    val output = socket.getOutputStream()
                    upstreamRequest.set(readHeaders(input))
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".toByteArray(Charsets.US_ASCII))
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: DENY
                allow:
                  - id: local
                    host: 127.0.0.1
                    methods: [GET]
                    paths: [/*]
                    header_rewrites:
                      - action: APPEND
                        header: X-Tags
                        value: oag-added
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = "GET http://127.0.0.1:${upstreamServer.localPort}/v1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Tags: original\r\nContent-Length: 0\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            val upstream = upstreamRequest.get()
            assertTrue(upstream.contains("original, oag-added") || upstream.contains("original,oag-added"),
                "Upstream should receive appended header value, got: $upstream")

            val event = firstAuditEvent(auditOut)
            val rewrites = event.headerRewrites
            assertNotNull(rewrites)
            assertEquals("append", rewrites[0].action)
        }
    }

    @Test
    fun `http header rewrite combined SET REMOVE APPEND all applied to upstream`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val upstreamRequest = AtomicReference("")
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    val input = socket.getInputStream()
                    val output = socket.getOutputStream()
                    upstreamRequest.set(readHeaders(input))
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".toByteArray(Charsets.US_ASCII))
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: DENY
                allow:
                  - id: local
                    host: 127.0.0.1
                    methods: [GET]
                    paths: [/*]
                    header_rewrites:
                      - action: SET
                        header: X-New
                        value: added
                      - action: REMOVE
                        header: X-Remove
                      - action: APPEND
                        header: X-Existing
                        value: more
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = "GET http://127.0.0.1:${upstreamServer.localPort}/v1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Remove: gone\r\nX-Existing: first\r\nContent-Length: 0\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            val upstream = upstreamRequest.get()
            assertTrue(upstream.contains("X-New: added"), "SET header should be present")
            assertFalse(upstream.contains("X-Remove"), "REMOVED header should be absent")
            assertTrue(upstream.contains("first, more") || upstream.contains("first,more"),
                "APPENDED value should be present")

            val event = firstAuditEvent(auditOut)
            val rewrites = event.headerRewrites!!
            assertEquals(3, rewrites.size)
        }
    }

    @Test
    fun `http request ID is injected into upstream headers`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)
            val upstreamRequest = AtomicReference<String>()

            thread(start = true) {
                upstreamServer.soTimeout = 5_000
                try {
                    upstreamServer.accept().use { client ->
                        val headers = readHeaders(client.getInputStream())
                        upstreamRequest.set(headers)
                        val response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                        client.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
                        client.getOutputStream().flush()
                    }
                } catch (_: Exception) {} finally {
                    served.countDown()
                }
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
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider, injectRequestId = true)

            val request = "GET http://127.0.0.1:${upstreamServer.localPort}/v1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            val upstream = upstreamRequest.get()
            assertTrue(upstream.lowercase().contains("x-request-id:"), "X-Request-Id should be present in upstream request")

            val event = firstAuditEvent(auditOut)
            assertNotNull(event.requestId, "Audit event should contain request_id")
        }
    }

    @Test
    fun `http request ID uses custom header name`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)
            val upstreamRequest = AtomicReference<String>()

            thread(start = true) {
                upstreamServer.soTimeout = 5_000
                try {
                    upstreamServer.accept().use { client ->
                        val headers = readHeaders(client.getInputStream())
                        upstreamRequest.set(headers)
                        val response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                        client.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
                        client.getOutputStream().flush()
                    }
                } catch (_: Exception) {} finally {
                    served.countDown()
                }
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
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider, injectRequestId = true, requestIdHeader = "X-Trace-Id")

            val request = "GET http://127.0.0.1:${upstreamServer.localPort}/v1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            val upstream = upstreamRequest.get()
            assertTrue(upstream.lowercase().contains("x-trace-id:"), "Custom header X-Trace-Id should be present in upstream request")
            assertFalse(upstream.lowercase().contains("x-request-id:"), "Default X-Request-Id should NOT be present when custom header is used")
        }
    }
}
