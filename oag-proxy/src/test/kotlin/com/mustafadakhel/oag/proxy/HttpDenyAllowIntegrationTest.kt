package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.pipeline.HostResolver
import com.mustafadakhel.oag.secrets.SecretProvider
import com.mustafadakhel.oag.secrets.SecretValue

import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal class HttpDenyAllowIntegrationTest : ProxyHandlerTestBase() {

    @Test
    fun `http deny returns 403 and does not open upstream connection`() = runTest {
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

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))
            assertTrue(acceptDone.await(5, TimeUnit.SECONDS))
            assertFalse(connected.get())
        }
    }

    @Test
    fun `http dry run forwards denied request and audits deny`() = runTest {
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
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider, dryRun = true)

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(upstreamRequest.get().startsWith("GET /v1/models HTTP/1.1"))

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("no_match_default_deny", event.decision.reasonCode)
        }
    }

    @Test
    fun `http blocks ip literal when enabled`() = runTest {
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

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

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
    fun `http redirect target is re-evaluated and blocked when denied`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write(
                        "HTTP/1.1 302 Found\r\nLocation: https://denied.example.com/v1\r\nContent-Length: 0\r\n\r\n"
                            .toByteArray(Charsets.US_ASCII)
                    )
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
                  - id: local-http
                    host: 127.0.0.1
                    methods: [GET]
                    paths: [/v1/*]
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                enforceRedirectPolicy = true
            )

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("redirect_target_denied", event.decision.reasonCode)
            assertEquals(1, event.redirectChain.size)
            assertEquals("https://denied.example.com/v1", event.redirectChain[0].location)
        }
    }

    @Test
    fun `http redirect target is blocked when raw ip literals are disabled`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write(
                        "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/v1\r\nContent-Length: 0\r\n\r\n"
                            .toByteArray(Charsets.US_ASCII)
                    )
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: ALLOW
                allow:
                  - id: local-http
                    host: localhost
                    methods: [GET]
                    paths: [/v1/*]
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                enforceRedirectPolicy = true,
                blockIpLiterals = true
            )

            val request = """
                GET http://localhost:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("raw_ip_literal_blocked", event.decision.reasonCode)
        }
    }

    @Test
    fun `http blocks private resolved ip when enabled`() = runTest {
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
            val resolver = HostResolver { host ->
                if (host == "localhost") listOf(InetAddress.getByName("127.0.0.1")) else emptyList()
            }
            val (handler, auditOut) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                blockPrivateResolvedIps = true,
                hostResolver = resolver
            )

            val request = """
                GET http://localhost:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))
            assertTrue(acceptDone.await(5, TimeUnit.SECONDS))
            assertFalse(connected.get())

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("dns_resolved_private_range_blocked", event.decision.reasonCode)
        }
    }

    @Test
    fun `http dry run allows private resolved ip but audits deny`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".toByteArray(Charsets.US_ASCII))
                    output.flush()
                }
                served.countDown()
            }

            val policyPath = writePolicy(
                """
                version: 1
                defaults:
                  action: ALLOW
                """.trimIndent()
            )
            val resolver = HostResolver { host ->
                if (host == "public.example.com") listOf(InetAddress.getByName("127.0.0.1")) else emptyList()
            }
            val (handler, auditOut) = createHandler(
                policyPath = policyPath,
                secretProvider = EmptySecretProvider,
                dryRun = true,
                blockPrivateResolvedIps = true,
                hostResolver = resolver
            )

            val request = """
                GET http://public.example.com:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertTrue(served.await(5, TimeUnit.SECONDS))

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("dns_resolved_private_range_blocked", event.decision.reasonCode)
        }
    }

    @Test
    fun `http dry run allows raw ip literal but audits deny`() = runTest {
        ServerSocket(0).use { upstreamServer ->
            val served = CountDownLatch(1)

            thread(start = true) {
                upstreamServer.accept().use { socket ->
                    readHeaders(socket.getInputStream())
                    val output = socket.getOutputStream()
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".toByteArray(Charsets.US_ASCII))
                    output.flush()
                }
                served.countDown()
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
                dryRun = true,
                blockIpLiterals = true
            )

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertTrue(served.await(5, TimeUnit.SECONDS))

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("raw_ip_literal_blocked", event.decision.reasonCode)
        }
    }

    @Test
    fun `http denies when dns resolution fails and policy enforces resolution`() = runTest {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: ALLOW
              enforce_dns_resolution: true
            """.trimIndent()
        )
        val (handler, auditOut) = createHandler(
            policyPath = policyPath,
            secretProvider = EmptySecretProvider,
            hostResolver = { emptyList() }
        )

        val request = """
            GET http://example.local/v1/models HTTP/1.1
            Host: ignored
            Content-Length: 0


        """.trimIndent().replace("\n", "\r\n")

        val responseOut = ByteArrayOutputStream()
        handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

        assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))
        val event = firstAuditEvent(auditOut)
        assertEquals("deny", event.decision.action)
        assertEquals("dns_resolution_failed", event.decision.reasonCode)
    }

    @Test
    fun `http allow forwards request and injects allowed secret`() = runTest {
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
                  - id: local-http
                    host: 127.0.0.1
                    methods: [GET]
                    paths: [/v1/*]
                    secrets: [API_KEY]
                """.trimIndent()
            )
            val secretProvider = object : SecretProvider {
                override fun resolve(secretId: String): SecretValue? =
                    if (secretId == "API_KEY") SecretValue("sekret", "v1") else null
            }
            val (handler, auditOut) = createHandler(policyPath, secretProvider)

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Authorization: OAG_PLACEHOLDER_API_KEY
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(upstreamRequest.get().contains("Authorization: sekret"))

            val event = firstAuditEvent(auditOut)
            assertEquals("allow", event.decision.action)
            assertEquals("allowed_by_rule", event.decision.reasonCode)
            assertTrue(event.secrets.injected)
            assertEquals("API_KEY", event.secrets.secretIds[0])
            assertEquals("v1", event.secrets.secretVersions["API_KEY"])
            assertFalse(auditOut.toString(Charsets.UTF_8).contains("sekret"))
        }
    }

    @Test
    fun `http allow denies when injected secret value contains non ascii header bytes`() = runTest {
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
                    methods: [GET]
                    paths: [/v1/*]
                    secrets: [API_KEY]
                """.trimIndent()
            )
            val secretProvider = object : SecretProvider {
                override fun resolve(secretId: String): SecretValue? =
                    if (secretId == "API_KEY") SecretValue("caf\u00E9") else null
            }
            val (handler, auditOut) = createHandler(policyPath, secretProvider)

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Authorization: OAG_PLACEHOLDER_API_KEY
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))
            assertTrue(acceptDone.await(5, TimeUnit.SECONDS))
            assertFalse(connected.get())

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("secret_materialization_failed", event.decision.reasonCode)
        }
    }

    @Test
    fun `http forward sets host header with non default port`() = runTest {
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
                  - id: local-http
                    host: 127.0.0.1
                    methods: [GET]
                    paths: [/v1/*]
                """.trimIndent()
            )
            val (handler, _) = createHandler(policyPath, EmptySecretProvider)

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 200 OK"))
            assertTrue(served.await(5, TimeUnit.SECONDS))
            assertTrue(upstreamRequest.get().contains("Host: 127.0.0.1:${upstreamServer.localPort}"))
        }
    }

    @Test
    fun `http allow denies when requested secret is not allowed by rule`() = runTest {
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
                    methods: [GET]
                    paths: [/v1/*]
                    secrets: [OTHER_SECRET]
                """.trimIndent()
            )
            val secretProvider = object : SecretProvider {
                override fun resolve(secretId: String): SecretValue? = SecretValue("sekret")
            }
            val (handler, auditOut) = createHandler(policyPath, secretProvider)

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Authorization: OAG_PLACEHOLDER_API_KEY
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))
            assertTrue(acceptDone.await(5, TimeUnit.SECONDS))
            assertFalse(connected.get())

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("secret_materialization_failed", event.decision.reasonCode)
        }
    }

    @Test
    fun `http deny when secret cannot be resolved blocks upstream and audits deny`() = runTest {
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
                    methods: [GET]
                    paths: [/v1/*]
                    secrets: [API_KEY]
                """.trimIndent()
            )
            val (handler, auditOut) = createHandler(policyPath, EmptySecretProvider)

            val request = """
                GET http://127.0.0.1:${upstreamServer.localPort}/v1/models HTTP/1.1
                Host: ignored
                Authorization: OAG_PLACEHOLDER_API_KEY
                Content-Length: 0


            """.trimIndent().replace("\n", "\r\n")

            val responseOut = ByteArrayOutputStream()
            handler.handle(ByteArrayInputStream(request.toByteArray(Charsets.US_ASCII)), responseOut)

            assertTrue(responseOut.toString(Charsets.UTF_8).startsWith("HTTP/1.1 403 Forbidden"))
            assertTrue(acceptDone.await(5, TimeUnit.SECONDS))
            assertFalse(connected.get())

            val event = firstAuditEvent(auditOut)
            assertEquals("deny", event.decision.action)
            assertEquals("secret_materialization_failed", event.decision.reasonCode)
        }
    }
}
