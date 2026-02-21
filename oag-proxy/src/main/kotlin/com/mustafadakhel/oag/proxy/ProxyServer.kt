package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.IdentityResult
import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.writeServiceUnavailable
import com.mustafadakhel.oag.proxy.tls.extractCertificateIdentity

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLServerSocketFactory
import javax.net.ssl.SSLSocket

internal class ProxyServer(
    private val listenHost: String,
    private val listenPort: Int,
    private val handler: ProxyHandler,
    private val config: HandlerConfig,
    private val clock: Clock = Clock.systemUTC(),
    private val maxThreads: Int = ProxyDefaults.MAX_THREADS,
    private val sslServerSocketFactory: SSLServerSocketFactory? = null
) {
    private val activeThreads = AtomicInteger(0)
    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var draining = false

    suspend fun start() {
        withContext(Dispatchers.IO) {
            val server = sslServerSocketFactory?.let { factory ->
                (factory.createServerSocket() as SSLServerSocket).apply { needClientAuth = true }
            } ?: ServerSocket()
            server.use {
                serverSocket = server
                server.reuseAddress = true
                server.bind(InetSocketAddress(listenHost, listenPort))
                coroutineScope {
                    while (!server.isClosed) {
                        val socket = runCatching { server.accept() }.getOrElse { break }
                        if (!tryAcquireSlot()) {
                            respondServiceUnavailable(socket)
                            continue
                        }
                        launch(Dispatchers.IO) {
                            try {
                                handleClient(socket)
                            } finally {
                                releaseSlot()
                            }
                        }
                    }
                }
            }
        }
    }

    fun stop() {
        runCatching { serverSocket?.close() }.onFailure { e ->
            System.err.println("${LOG_PREFIX}server socket close failed: ${e.message}")
        }
    }

    fun drain() {
        draining = true
        runCatching { serverSocket?.close() }.onFailure { e ->
            System.err.println("${LOG_PREFIX}server socket close failed during drain: ${e.message}")
        }
    }

    val isDraining: Boolean get() = draining

    val localPort: Int get() = serverSocket?.localPort ?: -1

    val activeConnectionCount: Int get() = activeThreads.get()

    suspend fun awaitDrain(timeoutMs: Long): Boolean {
        val deadline = clock.millis() + timeoutMs
        while (activeConnectionCount > 0 && clock.millis() < deadline) {
            delay(100)
        }
        return activeConnectionCount == 0
    }

    fun awaitDrainBlocking(timeoutMs: Long): Boolean = runBlocking {
        awaitDrain(timeoutMs)
    }

    private suspend fun handleClient(socket: Socket) {
        socket.use { client ->
            client.soTimeout = config.network.readTimeoutMs
            val input = BufferedInputStream(client.getInputStream())
            val output = BufferedOutputStream(client.getOutputStream())
            val identity = extractMtlsIdentity(client)
            handler.handle(input, output, clientSocket = client, connectionIdentity = identity)
        }
    }

    private fun respondServiceUnavailable(socket: Socket) {
        socket.use { client ->
            runCatching {
                writeServiceUnavailable(BufferedOutputStream(client.getOutputStream()))
            }
        }
    }

    private fun tryAcquireSlot(): Boolean {
        if (draining) return false
        while (true) {
            val current = activeThreads.get()
            if (current >= maxThreads) return false
            if (activeThreads.compareAndSet(current, current + 1)) return true
        }
    }

    private fun releaseSlot() {
        activeThreads.decrementAndGet()
    }

    private fun extractMtlsIdentity(socket: Socket): IdentityResult? =
        (socket as? SSLSocket)
            ?.let { runCatching { it.session.peerCertificates }.getOrNull() }
            ?.firstOrNull()
            ?.let { it as? X509Certificate }
            ?.let { extractCertificateIdentity(it) }
}
