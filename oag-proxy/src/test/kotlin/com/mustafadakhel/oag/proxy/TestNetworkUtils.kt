package com.mustafadakhel.oag.proxy

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

import java.net.Socket

internal suspend fun awaitServerReady(port: Int) = withContext(Dispatchers.IO) {
    val deadline = System.currentTimeMillis() + 3_000
    while (System.currentTimeMillis() < deadline) {
        runCatching { Socket("127.0.0.1", port).close() }.onSuccess { return@withContext }
        delay(10)
    }
    error("Server did not start within 3 seconds on port $port")
}

internal suspend fun awaitServerReady(server: ProxyServer) = withContext(Dispatchers.IO) {
    val deadline = System.currentTimeMillis() + 3_000
    while (server.localPort <= 0 && System.currentTimeMillis() < deadline) {
        delay(10)
    }
    check(server.localPort > 0) { "Server did not bind within 3 seconds" }
}
