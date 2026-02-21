package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.proxy.tls.HostCertificateCache
import com.mustafadakhel.oag.proxy.tls.generateCaBundle
import com.mustafadakhel.oag.proxy.tls.buildServerSslContext
import com.mustafadakhel.oag.proxy.tls.buildUpstreamSslContext
import com.mustafadakhel.oag.proxy.tls.buildClientTrustingSslContext

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class MitmSslContextFactoryTest {

    private val caBundle = generateCaBundle()
    private val cache = HostCertificateCache(caBundle)

    @Test
    fun `buildServerSslContext creates valid SSLContext`() {
        val hostCert = cache.getOrCreate("api.example.com")
        val sslContext = buildServerSslContext(hostCert, caBundle)

        assertNotNull(sslContext)
        assertTrue(sslContext.protocol.startsWith("TLS"), "Protocol should be TLS, got: ${sslContext.protocol}")
    }

    @Test
    fun `buildUpstreamSslContext creates valid SSLContext`() {
        val sslContext = buildUpstreamSslContext()

        assertNotNull(sslContext)
        assertTrue(sslContext.protocol.startsWith("TLS"), "Protocol should be TLS, got: ${sslContext.protocol}")
    }

    @Test
    fun `buildClientTrustingSslContext creates valid SSLContext`() {
        val sslContext = buildClientTrustingSslContext(caBundle)

        assertNotNull(sslContext)
        assertTrue(sslContext.protocol.startsWith("TLS"), "Protocol should be TLS, got: ${sslContext.protocol}")
    }

    @Test
    fun `server SSLContext can create SSLEngine`() {
        val hostCert = cache.getOrCreate("api.example.com")
        val sslContext = buildServerSslContext(hostCert, caBundle)

        val engine = sslContext.createSSLEngine()
        assertNotNull(engine)
    }

    @Test
    fun `CA-signed host certificate verifies against CA public key`() {
        val hostCert = cache.getOrCreate("api.example.com")
        val trustCtx = buildClientTrustingSslContext(caBundle)
        val tmf = trustCtx.createSSLEngine()

        assertNotNull(tmf, "SSLEngine should be created from trusting context")

        hostCert.certificate.verify(caBundle.keyPair.public)
    }

    @Test
    fun `server and client contexts work for same hostname`() {
        val hostCert = cache.getOrCreate("api.openai.com")
        val serverCtx = buildServerSslContext(hostCert, caBundle)
        val clientCtx = buildClientTrustingSslContext(caBundle)

        val serverEngine = serverCtx.createSSLEngine()
        serverEngine.useClientMode = false

        val clientEngine = clientCtx.createSSLEngine("api.openai.com", 443)
        clientEngine.useClientMode = true

        assertNotNull(serverEngine)
        assertNotNull(clientEngine)
    }
}
