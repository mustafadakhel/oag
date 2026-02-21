package com.mustafadakhel.oag.policy.lifecycle

import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.file.Files

class PolicyFetcherTest {

    @Test
    fun `fetch downloads and caches policy`() {
        val content = "version: 1\ndefaults:\n  action: deny\n"
        val port = startMockServer(200, content)
        val cachePath = Files.createTempFile("policy-cache-", ".yaml")
        Files.deleteIfExists(cachePath)

        val fetcher = PolicyFetcher(PolicyFetchConfig(
            url = "http://127.0.0.1:$port/policy.yaml",
            cachePath = cachePath
        ))

        val result = fetcher.fetch()
        assertTrue(result.changed)
        assertTrue(result.bytesDownloaded > 0)
        assertEquals(content, Files.readString(cachePath))
    }

    @Test
    fun `second fetch with same content returns unchanged`() {
        val content = "version: 1\ndefaults:\n  action: deny\n"
        val port = startMockServer(200, content)
        val cachePath = Files.createTempFile("policy-cache-", ".yaml")
        Files.deleteIfExists(cachePath)

        val fetcher = PolicyFetcher(PolicyFetchConfig(
            url = "http://127.0.0.1:$port/policy.yaml",
            cachePath = cachePath
        ))

        val first = fetcher.fetch()
        assertTrue(first.changed)

        val second = fetcher.fetch()
        assertFalse(second.changed)
        assertEquals(first.contentHash, second.contentHash)
    }

    @Test
    fun `fetch throws on HTTP error`() {
        val port = startMockServer(500, "internal error")
        val cachePath = Files.createTempFile("policy-cache-", ".yaml")

        val fetcher = PolicyFetcher(PolicyFetchConfig(
            url = "http://127.0.0.1:$port/policy.yaml",
            cachePath = cachePath
        ))

        assertFailsWith<PolicyFetchException> {
            fetcher.fetch()
        }
    }

    @Test
    fun `fetch to unreachable host throws`() {
        val cachePath = Files.createTempFile("policy-cache-", ".yaml")

        val fetcher = PolicyFetcher(PolicyFetchConfig(
            url = "http://127.0.0.1:1/policy.yaml",
            cachePath = cachePath,
            timeoutMs = 500
        ))

        assertFailsWith<Exception> {
            fetcher.fetch()
        }
    }

    @Test
    fun `content hash is deterministic`() {
        val content = "version: 1\n"
        val port = startMockServer(200, content)
        val cachePath = Files.createTempFile("policy-cache-", ".yaml")
        Files.deleteIfExists(cachePath)

        val fetcher = PolicyFetcher(PolicyFetchConfig(
            url = "http://127.0.0.1:$port/policy.yaml",
            cachePath = cachePath
        ))

        val result = fetcher.fetch()
        assertTrue(result.contentHash.length == 64)
        assertTrue(result.contentHash.all { it in '0'..'9' || it in 'a'..'f' })
    }

    private val mockServers = mutableListOf<ServerSocket>()

    @AfterTest
    fun tearDown() {
        mockServers.forEach { runCatching { it.close() } }
        mockServers.clear()
    }

    private fun startMockServer(statusCode: Int, body: String): Int {
        val server = ServerSocket()
        server.reuseAddress = true
        server.bind(InetSocketAddress("127.0.0.1", 0))
        val port = server.localPort
        mockServers.add(server)
        thread(start = true, isDaemon = true) {
            while (!server.isClosed) {
                val client = runCatching { server.accept() }.getOrElse { break }
                thread(start = true, isDaemon = true) {
                    client.use { socket ->
                        val reader = socket.getInputStream().bufferedReader()
                        while (true) {
                            val line = reader.readLine() ?: break
                            if (line.isEmpty()) break
                        }
                        val bodyBytes = body.toByteArray(Charsets.UTF_8)
                        val statusText = if (statusCode == 200) "OK" else "Error"
                        val response = "HTTP/1.1 $statusCode $statusText\r\nContent-Length: ${bodyBytes.size}\r\nConnection: close\r\n\r\n"
                        socket.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
                        socket.getOutputStream().write(bodyBytes)
                        socket.getOutputStream().flush()
                    }
                }
            }
        }
        return port
    }
}
