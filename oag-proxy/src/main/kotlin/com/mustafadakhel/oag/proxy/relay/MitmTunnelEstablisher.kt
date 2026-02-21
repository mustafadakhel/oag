package com.mustafadakhel.oag.proxy.relay

import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.relay.UpstreamConnector
import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.enforcement.recordConnectionSuccess
import com.mustafadakhel.oag.proxy.tls.CaBundle
import com.mustafadakhel.oag.proxy.tls.HostCertificateCache
import com.mustafadakhel.oag.proxy.tls.buildServerSslContext
import com.mustafadakhel.oag.proxy.tls.buildUpstreamSslContext

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import javax.net.ssl.SSLSocket

internal class MitmSslTunnel(
    val clientInput: InputStream,
    val clientOutput: OutputStream,
    val upstreamInput: InputStream,
    val upstreamOutput: OutputStream,
    private val clientSslSocket: SSLSocket,
    private val upstreamSslSocket: SSLSocket,
    private val upstreamSocket: Socket,
    private val debugLog: ((() -> String) -> Unit)
) : Closeable {
    override fun close() {
        runCatching { clientSslSocket.close() }.onFailure { e -> debugLog { "client SSL close failed: ${e.message}" } }
        runCatching { upstreamSslSocket.close() }.onFailure { e -> debugLog { "upstream SSL close failed: ${e.message}" } }
        runCatching { upstreamSocket.close() }.onFailure { e -> debugLog { "upstream close failed: ${e.message}" } }
    }
}

internal fun interface MitmTunnelEstablisher {
    fun establish(context: RequestPipelineContext): MitmSslTunnel
}

internal fun buildMitmTunnelEstablisher(
    upstreamConnector: UpstreamConnector,
    circuitBreakerRegistry: CircuitBreakerRegistry?,
    hostCertificateCache: HostCertificateCache,
    caBundle: CaBundle
): MitmTunnelEstablisher = MitmTunnelEstablisher { context ->
    val mitmReadTimeout = context.matchedRule?.readTimeoutMs ?: context.config.network.readTimeoutMs
    val upstream = upstreamConnector.openSocket(
        target = context.target,
        resolvedIps = context.resolvedIps,
        ruleConnectTimeoutMs = context.matchedRule?.connectTimeoutMs,
        ruleReadTimeoutMs = context.matchedRule?.readTimeoutMs
    )
    circuitBreakerRegistry.recordConnectionSuccess(context.target.host)
    context.output.write(HttpConstants.CONNECT_ESTABLISHED_RESPONSE)
    context.output.flush()

    val hostCert = hostCertificateCache.getOrCreate(context.target.host)
    val serverSslContext = buildServerSslContext(hostCert, caBundle)
    val upstreamSslContext = buildUpstreamSslContext()

    val clientSslSocket = (serverSslContext.socketFactory.createSocket(
        requireNotNull(context.clientSocket) { "clientSocket required for MITM" },
        context.target.host, context.target.port, false
    ) as SSLSocket).apply {
        useClientMode = false
        soTimeout = mitmReadTimeout
        startHandshake()
    }

    val upstreamSslSocket = (upstreamSslContext.socketFactory.createSocket(
        upstream, context.target.host, context.target.port, true
    ) as SSLSocket).apply {
        useClientMode = true
        soTimeout = mitmReadTimeout
        startHandshake()
    }

    MitmSslTunnel(
        clientInput = BufferedInputStream(clientSslSocket.inputStream),
        clientOutput = BufferedOutputStream(clientSslSocket.outputStream),
        upstreamInput = BufferedInputStream(upstreamSslSocket.inputStream),
        upstreamOutput = BufferedOutputStream(upstreamSslSocket.outputStream),
        clientSslSocket = clientSslSocket,
        upstreamSslSocket = upstreamSslSocket,
        upstreamSocket = upstream,
        debugLog = context.debugLog
    )
}
