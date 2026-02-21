package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.LOG_PREFIX

import java.net.Socket
import java.time.Clock
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

private fun Socket.isHealthy(): Boolean =
    !isClosed && isConnected && !isInputShutdown && !isOutputShutdown

data class PoolKey(val host: String, val port: Int)

private data class PooledSocket(
    val socket: Socket,
    val returnedAt: Long
)

data class PoolStats(
    val hits: Long,
    val misses: Long,
    val evictions: Long,
    val currentIdle: Int
)

class ConnectionPool(
    private val maxIdlePerHost: Int = 8,
    private val idleTimeoutMs: Long = 60_000,
    private val clock: Clock = Clock.systemUTC(),
    private val onError: (String) -> Unit = System.err::println
) {
    private val pool = ConcurrentHashMap<PoolKey, ArrayDeque<PooledSocket>>()
    private val hits = AtomicLong()
    private val misses = AtomicLong()
    private val evictions = AtomicLong()

    fun acquire(host: String, port: Int): Socket? {
        val key = PoolKey(host, port)
        val deque = pool[key] ?: run {
            misses.incrementAndGet()
            return null
        }
        val now = clock.millis()
        val toClose = mutableListOf<Socket>()
        try {
            synchronized(deque) {
                while (true) {
                    val entry = deque.pollLast() ?: run {
                        misses.incrementAndGet()
                        return null
                    }
                    if (now - entry.returnedAt > idleTimeoutMs) {
                        evictions.incrementAndGet()
                        toClose += entry.socket
                        continue
                    }
                    if (!entry.socket.isHealthy()) {
                        toClose += entry.socket
                        continue
                    }
                    hits.incrementAndGet()
                    return entry.socket
                }
            }
        } finally {
            toClose.forEach { socket ->
                runCatching { socket.close() }.onFailure { e ->
                    onError("${LOG_PREFIX}pool acquire close failed: ${e.message}")
                }
            }
        }
    }

    fun release(host: String, port: Int, socket: Socket) {
        if (!socket.isHealthy()) {
            runCatching { socket.close() }.onFailure { e ->
                onError("${LOG_PREFIX}pool release close failed: ${e.message}")
            }
            return
        }
        val key = PoolKey(host, port)
        val deque = pool.computeIfAbsent(key) { ArrayDeque() }
        synchronized(deque) {
            if (deque.size >= maxIdlePerHost) {
                evictions.incrementAndGet()
                runCatching { socket.close() }.onFailure { e ->
                    onError("${LOG_PREFIX}pool overflow close failed: ${e.message}")
                }
                return
            }
            deque.addLast(PooledSocket(socket, clock.millis()))
        }
    }

    fun evictExpired(): Int {
        var count = 0
        val now = clock.millis()
        for ((_, deque) in pool) {
            val toClose = mutableListOf<Socket>()
            synchronized(deque) {
                val iter = deque.iterator()
                while (iter.hasNext()) {
                    val entry = iter.next()
                    if (now - entry.returnedAt > idleTimeoutMs || entry.socket.isClosed) {
                        iter.remove()
                        toClose += entry.socket
                        evictions.incrementAndGet()
                        count++
                    }
                }
            }
            toClose.forEach { socket ->
                runCatching { socket.close() }.onFailure { e ->
                    onError("${LOG_PREFIX}pool expired evict close failed: ${e.message}")
                }
            }
        }
        return count
    }

    fun stats(): PoolStats {
        val idle = pool.values.sumOf { deque -> synchronized(deque) { deque.size } }
        return PoolStats(
            hits = hits.get(),
            misses = misses.get(),
            evictions = evictions.get(),
            currentIdle = idle
        )
    }

    fun close() {
        for ((_, deque) in pool) {
            val toClose = synchronized(deque) {
                val entries = deque.map { it.socket }
                deque.clear()
                entries
            }
            toClose.forEach { socket ->
                runCatching { socket.close() }.onFailure { e ->
                    onError("${LOG_PREFIX}pool shutdown close failed: ${e.message}")
                }
            }
        }
        pool.clear()
    }
}
