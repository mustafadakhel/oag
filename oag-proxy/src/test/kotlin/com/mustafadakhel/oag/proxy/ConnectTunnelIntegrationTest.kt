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

internal class ConnectTunnelIntegrationTest : ProxyHandlerTestBase() {

    @Test
    fun `connect deny returns 403 and does not open upstream connection`() = runTest {
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
                """.trimIndent()
            )
            val (handler, _) = createHandler(policyPath, EmptySecretProvider)

            val request = "CONNECT 127.0.0.1:${upstreamServer.localPort} HTTP/1.1\r\nHost: ignored\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))
            assertTrue(acceptDone.await(5, TimeUnit.SECONDS))
            assertFalse(connected.get())
        }
    }

    @Test
    fun `connect dry run establishes tunnel while auditing deny`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val connected = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use {
                    connected.countDown()
                }
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: DENY
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider, dryRun = true)

            val request = "CONNECT 127.0.0.1:${upstreamServer.localPort} HTTP/1.1\r\nHost: ignored\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 Connection Established"))
            assertTrue(connected.await(5, TimeUnit.SECONDS))

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("no_match_default_deny", event.decision.reasonCode)
        }
    }

    @Test
    fun `connect blocks ip literal when enabled`() = runTest {
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
                  action: ALLOW
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                blockIpLiterals = true
            )

            val request = "CONNECT 127.0.0.1:${upstreamServer.localPort} HTTP/1.1\r\nHost: ignored\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))
            assertTrue(acceptDone.await(5, TimeUnit.SECONDS))
            assertFalse(connected.get())

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("raw_ip_literal_blocked", event.decision.reasonCode)
        }
    }

    @Test
    fun `connect allow establishes tunnel and audits allow`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val connected = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use {
                    connected.countDown()
                }
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: DENY
                allow:
                  - id: local-connect
                    host: 127.0.0.1
                    methods: [CONNECT]
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = "CONNECT 127.0.0.1:${upstreamServer.localPort} HTTP/1.1\r\nHost: ignored\r\n\r\n"
            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 Connection Established"))
            assertTrue(connected.await(5, TimeUnit.SECONDS))

            val event = firstAuditEvent(auditOut)
            assertEquals("allow", event.decision.action)
            assertEquals("allowed_by_rule", event.decision.reasonCode)
        }
    }

    @Test
    fun `connect upstream connection failure returns 502 and audits deny`() = runTest {
        val closedPort = ServerSocket(0).use { it.localPort }
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: local-connect
                host: 127.0.0.1
                methods: [CONNECT]
            """.trimIndent()
        )
        val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

        val request = "CONNECT 127.0.0.1:$closedPort HTTP/1.1\r\nHost: ignored\r\n\r\n"
        val responseOut = ByteArrayOutputStream()
        handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

        assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 502 Bad Gateway"))
        val event = firstAuditEvent(auditOut)
        assertEquals("deny", event.decision.action)
        assertEquals("upstream_connection_failed", event.decision.reasonCode)
    }
}
