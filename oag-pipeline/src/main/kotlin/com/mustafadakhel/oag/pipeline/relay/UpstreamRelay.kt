package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.BackoffStrategy
import com.mustafadakhel.oag.RetryExhaustedException
import com.mustafadakhel.oag.RetryPolicy
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.inspection.RequestBodyException
import com.mustafadakhel.oag.policy.core.PolicyRetry
import com.mustafadakhel.oag.telemetry.DebugLogger
import com.mustafadakhel.oag.withSuspendRetry

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

data class ConnectResult(val socket: Socket, val attempts: Int)

class UpstreamConnector(
    private val connectTimeoutMs: Int,
    private val readTimeoutMs: Int,
    private val debugLogger: DebugLogger
) {
    fun openSocket(
        target: ParsedTarget,
        resolvedIps: List<InetAddress>,
        ruleConnectTimeoutMs: Int? = null,
        ruleReadTimeoutMs: Int? = null
    ): Socket {
        val socket = Socket()
        socket.soTimeout = ruleReadTimeoutMs ?: readTimeoutMs
        val resolved = resolvedIps.firstOrNull()
        val socketAddress = if (resolved != null) {
            InetSocketAddress(resolved, target.port)
        } else {
            InetSocketAddress(target.host, target.port)
        }
        socket.connect(socketAddress, ruleConnectTimeoutMs ?: connectTimeoutMs)
        return socket
    }

    suspend fun retryConnect(
        target: ParsedTarget,
        resolvedIps: List<InetAddress>,
        ruleConnectTimeoutMs: Int?,
        ruleReadTimeoutMs: Int?,
        retryPolicy: RetryPolicy
    ): ConnectResult {
        var attempts = 0
        val socket = withSuspendRetry(
            policy = retryPolicy,
            onFailure = { attempt, e ->
                attempts = attempt
                debugLogger.log { "upstream connect attempt $attempt failed: ${e.message}" }
            }
        ) {
            openSocket(target = target, resolvedIps = resolvedIps, ruleConnectTimeoutMs = ruleConnectTimeoutMs, ruleReadTimeoutMs = ruleReadTimeoutMs)
        }
        return ConnectResult(socket, attempts)
    }
}

fun PolicyRetry?.toRetryPolicy(defaultDelayMs: Long = 100L): RetryPolicy = RetryPolicy(
    maxAttempts = (this?.maxRetries ?: 0) + 1,
    backoffStrategy = BackoffStrategy.fixed(this?.retryDelayMs ?: defaultDelayMs)
)

fun forwardRequestBody(
    request: HttpRequest,
    clientInput: InputStream,
    upstreamOut: OutputStream,
    preBuffered: ByteArray? = null
): Long {
    val contentLength = request.headers[HttpConstants.CONTENT_LENGTH]?.toLongOrNull() ?: return 0L
    if (contentLength <= 0) return 0L

    if (preBuffered != null) {
        upstreamOut.write(preBuffered)
        val remaining = contentLength - preBuffered.size
        if (remaining > 0) {
            return preBuffered.size.toLong() + streamBytes(clientInput, upstreamOut, remaining)
        }
        return preBuffered.size.toLong()
    }

    val total = streamBytes(clientInput, upstreamOut, contentLength)
    if (total != contentLength) throw RequestBodyException.Truncated()
    return total
}

fun streamBytes(input: InputStream, output: OutputStream, count: Long): Long =
    relayBytes(input, output, count) { e ->
        when (e) {
            is SocketTimeoutException -> throw RequestBodyException.Timeout()
            is IOException -> throw RequestBodyException.ReadFailure()
            else -> throw e
        }
    }
