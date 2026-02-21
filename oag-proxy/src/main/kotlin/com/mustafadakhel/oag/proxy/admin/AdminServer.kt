package com.mustafadakhel.oag.proxy.admin

import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.support.IpRange
import com.mustafadakhel.oag.policy.support.contains
import com.mustafadakhel.oag.policy.support.parseIpRange
import com.mustafadakhel.oag.proxy.ProxyDefaults
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.HttpStatus

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext

import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.Locale

internal data class PolicyInfo(
    val hash: String,
    val allowRuleCount: Int,
    val denyRuleCount: Int,
    val loadedAt: String
)

internal class AdminServer(
    private val listenHost: String = ProxyDefaults.ADMIN_LISTEN_HOST,
    private val listenPort: Int,
    private val deps: AdminServerDeps,
    private val adminAccessCallback: AdminAccessCallback? = null,
    allowedIps: List<String> = emptyList(),
    private val adminToken: String? = null
) : AutoCloseable {

    private val allowedExact: Set<InetAddress>
    private val allowedRanges: List<IpRange>

    init {
        val (rangeEntries, exactEntries) = allowedIps.partition { it.contains("/") }
        allowedExact = exactEntries.map { InetAddress.getByName(it) }.toSet()
        allowedRanges = rangeEntries.map { parseIpRange(it) }
    }

    private val handler = AdminRequestHandler(deps)

    private val connectionSemaphore = Semaphore(MAX_CONCURRENT_ADMIN)

    @Volatile private var serverSocket: ServerSocket? = null

    suspend fun start() {
        withContext(Dispatchers.IO) {
            ServerSocket().use { server ->
                serverSocket = server
                server.reuseAddress = true
                server.bind(InetSocketAddress(listenHost, listenPort))
                coroutineScope {
                    while (!server.isClosed) {
                        val socket = runCatching { server.accept() }.getOrElse { break }
                        if (!connectionSemaphore.tryAcquire()) {
                            runCatching {
                                socket.use { s ->
                                    writeAdminResponse(
                                        s.getOutputStream(),
                                        HttpStatus.SERVICE_UNAVAILABLE.code,
                                        HttpConstants.APPLICATION_JSON,
                                        encodeAdminJson(AdminErrorResponse(ok = false, error = "too many admin connections"))
                                    )
                                }
                            }
                            continue
                        }
                        launch(Dispatchers.IO) {
                            try {
                                handleConnection(socket)
                            } finally {
                                connectionSemaphore.release()
                            }
                        }
                    }
                }
            }
        }
    }

    companion object {
        private const val MAX_CONCURRENT_ADMIN = 16
        private const val ADMIN_SOCKET_TIMEOUT_MS = 5_000
        private const val AUTHORIZATION_PREFIX = "Authorization:"
        private const val BEARER_PREFIX = "Bearer "
    }

    fun stop() {
        runCatching { serverSocket?.close() }.onFailure { e ->
            System.err.println("${LOG_PREFIX}admin server socket close failed: ${e.message}")
        }
    }

    override fun close() = stop()

    private fun isAllowed(address: InetAddress): Boolean {
        if (allowedExact.isEmpty() && allowedRanges.isEmpty()) return true
        if (address in allowedExact) return true
        return allowedRanges.any { it.contains(address) }
    }

    private data class AdminRequest(
        val method: String,
        val path: String,
        val authHeader: String?,
        val clientAddress: InetAddress?,
        val sourceIp: String
    )

    private fun handleConnection(socket: Socket) {
        socket.use { client ->
            client.soTimeout = ADMIN_SOCKET_TIMEOUT_MS
            val request = parseAdminRequest(client) ?: return
            val output = BufferedOutputStream(client.getOutputStream())
            if (!authorize(request, output)) return
            adminAccessCallback?.onAccess(request.path, request.sourceIp, EnforcementAction.Allow)
            handler.handle(request.method, request.path, output)
        }
    }

    private fun parseAdminRequest(client: Socket): AdminRequest? {
        val clientAddress = (client.remoteSocketAddress as? InetSocketAddress)?.address
        val reader = BufferedReader(InputStreamReader(client.getInputStream(), Charsets.US_ASCII))
        val requestLine = runCatching { reader.readLine() }.getOrNull() ?: return null

        var authHeader: String? = null
        while (true) {
            val line = runCatching { reader.readLine() }.getOrNull() ?: break
            if (line.isEmpty()) break
            if (line.startsWith(AUTHORIZATION_PREFIX, ignoreCase = true)) {
                authHeader = line.substringAfter(":").trim()
            }
        }

        val parts = requestLine.split(" ")
        return AdminRequest(
            method = parts.getOrNull(0)?.uppercase(Locale.ROOT) ?: HttpConstants.METHOD_GET,
            path = parts.getOrNull(1) ?: "/",
            authHeader = authHeader,
            clientAddress = clientAddress,
            sourceIp = clientAddress?.hostAddress ?: "unknown"
        )
    }

    private fun authorize(
        request: AdminRequest,
        output: BufferedOutputStream
    ): Boolean {
        if (request.clientAddress != null && !isAllowed(request.clientAddress)) {
            denyAndRespond(output, request.path, request.sourceIp, HttpStatus.FORBIDDEN)
            return false
        }
        if (adminToken != null && request.path != AdminPath.HEALTHZ.path && !checkBearerToken(request.authHeader)) {
            denyAndRespond(output, request.path, request.sourceIp, HttpStatus.UNAUTHORIZED)
            return false
        }
        return true
    }

    private fun denyAndRespond(output: BufferedOutputStream, path: String, sourceIp: String, status: HttpStatus) {
        val reason = status.label()
        val action = EnforcementAction.Deny(reason = reason, statusCode = status.code)
        adminAccessCallback?.onAccess(path, sourceIp, action)
        writeAdminResponse(output, status.code, HttpConstants.APPLICATION_JSON, encodeAdminJson(
            AdminErrorResponse(ok = false, error = reason)
        ))
    }

    private fun checkBearerToken(authHeader: String?): Boolean {
        if (authHeader == null) return false
        if (!authHeader.startsWith(BEARER_PREFIX, ignoreCase = true)) return false
        val provided = authHeader.substring(BEARER_PREFIX.length).trim()
        return MessageDigest.isEqual(
            provided.toByteArray(Charsets.UTF_8),
            requireNotNull(adminToken) { "adminToken must be set for auth check" }.toByteArray(Charsets.UTF_8)
        )
    }
}
