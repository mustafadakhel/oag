package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.enforcement.ConnectionPool

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

import java.net.ServerSocket
import java.net.Socket

class ConnectionPoolTest {
    @Test
    fun `acquire returns null when pool is empty`() {
        val pool = ConnectionPool(maxIdlePerHost = 4, idleTimeoutMs = 60_000)
        assertNull(pool.acquire("api.example.com", 443))
    }

    @Test
    fun `release and acquire returns same socket`() {
        ServerSocket(0).use { server ->
            val socket = Socket("127.0.0.1", server.localPort)
            val pool = ConnectionPool(maxIdlePerHost = 4, idleTimeoutMs = 60_000)

            pool.release("127.0.0.1", server.localPort, socket)
            val acquired = pool.acquire("127.0.0.1", server.localPort)

            assertNotNull(acquired)
            assertEquals(socket, acquired)
            acquired.close()
            pool.close()
        }
    }

    @Test
    fun `acquire returns null for different host`() {
        ServerSocket(0).use { server ->
            val socket = Socket("127.0.0.1", server.localPort)
            val pool = ConnectionPool(maxIdlePerHost = 4, idleTimeoutMs = 60_000)

            pool.release("127.0.0.1", server.localPort, socket)
            assertNull(pool.acquire("other.host", server.localPort))

            pool.close()
        }
    }

    @Test
    fun `max idle per host is enforced`() {
        ServerSocket(0).use { server ->
            val pool = ConnectionPool(maxIdlePerHost = 2, idleTimeoutMs = 60_000)

            val s1 = Socket("127.0.0.1", server.localPort)
            val s2 = Socket("127.0.0.1", server.localPort)
            val s3 = Socket("127.0.0.1", server.localPort)

            pool.release("127.0.0.1", server.localPort, s1)
            pool.release("127.0.0.1", server.localPort, s2)
            pool.release("127.0.0.1", server.localPort, s3)

            val stats = pool.stats()
            assertEquals(2, stats.currentIdle)
            assertEquals(1, stats.evictions)

            pool.close()
        }
    }

    @Test
    fun `expired connections are evicted on acquire`() = runBlocking {
        ServerSocket(0).use { server ->
            val pool = ConnectionPool(maxIdlePerHost = 4, idleTimeoutMs = 1)

            val socket = Socket("127.0.0.1", server.localPort)
            pool.release("127.0.0.1", server.localPort, socket)
            delay(10)

            val acquired = pool.acquire("127.0.0.1", server.localPort)
            assertNull(acquired)

            pool.close()
        }
    }

    @Test
    fun `evictExpired removes old connections`() = runBlocking {
        ServerSocket(0).use { server ->
            val pool = ConnectionPool(maxIdlePerHost = 4, idleTimeoutMs = 1)

            pool.release("127.0.0.1", server.localPort, Socket("127.0.0.1", server.localPort))
            pool.release("127.0.0.1", server.localPort, Socket("127.0.0.1", server.localPort))
            delay(10)

            val evicted = pool.evictExpired()
            assertTrue(evicted >= 2)
            assertEquals(0, pool.stats().currentIdle)

            pool.close()
        }
    }

    @Test
    fun `closed socket is not returned from acquire`() {
        ServerSocket(0).use { server ->
            val pool = ConnectionPool(maxIdlePerHost = 4, idleTimeoutMs = 60_000)

            val socket = Socket("127.0.0.1", server.localPort)
            socket.close()
            pool.release("127.0.0.1", server.localPort, socket)

            assertEquals(0, pool.stats().currentIdle)
            pool.close()
        }
    }

    @Test
    fun `stats tracks hits and misses`() {
        ServerSocket(0).use { server ->
            val pool = ConnectionPool(maxIdlePerHost = 4, idleTimeoutMs = 60_000)

            pool.acquire("127.0.0.1", server.localPort)
            assertEquals(1, pool.stats().misses)

            val socket = Socket("127.0.0.1", server.localPort)
            pool.release("127.0.0.1", server.localPort, socket)
            val acquired = pool.acquire("127.0.0.1", server.localPort)
            assertNotNull(acquired)
            assertEquals(1, pool.stats().hits)

            acquired.close()
            pool.close()
        }
    }

    @Test
    fun `close closes all pooled sockets`() {
        ServerSocket(0).use { server ->
            val pool = ConnectionPool(maxIdlePerHost = 4, idleTimeoutMs = 60_000)

            val s1 = Socket("127.0.0.1", server.localPort)
            val s2 = Socket("127.0.0.1", server.localPort)
            pool.release("127.0.0.1", server.localPort, s1)
            pool.release("127.0.0.1", server.localPort, s2)
            assertEquals(2, pool.stats().currentIdle)

            pool.close()
            assertEquals(0, pool.stats().currentIdle)
            assertTrue(s1.isClosed)
            assertTrue(s2.isClosed)
        }
    }
}
