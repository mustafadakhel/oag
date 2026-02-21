package com.mustafadakhel.oag.proxy.tls

import org.bouncycastle.jce.provider.BouncyCastleProvider

import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

private const val SSL_PROTOCOL = "TLS"
private const val KEYSTORE_TYPE = "PKCS12"
private val EMPTY_PASSWORD = charArrayOf()
private const val HOST_KEY_ALIAS = "host"
private const val CA_CERT_ALIAS = "oag-ca"

internal fun buildServerSslContext(hostCert: HostCertificate, caBundle: CaBundle): SSLContext {
    installBouncyCastleProvider()
    val keyStore = KeyStore.getInstance(KEYSTORE_TYPE, BouncyCastleProvider.PROVIDER_NAME).apply {
        load(null, null)
        setKeyEntry(
            HOST_KEY_ALIAS,
            hostCert.keyPair.private,
            EMPTY_PASSWORD,
            arrayOf(hostCert.certificate, caBundle.certificate)
        )
    }

    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    kmf.init(keyStore, EMPTY_PASSWORD)

    val sslContext = SSLContext.getInstance(SSL_PROTOCOL)
    sslContext.init(kmf.keyManagers, null, null)
    return sslContext
}

internal fun buildUpstreamSslContext(): SSLContext {
    val sslContext = SSLContext.getInstance(SSL_PROTOCOL)
    sslContext.init(null, null, null)
    return sslContext
}

internal fun buildClientTrustingSslContext(caBundle: CaBundle): SSLContext {
    installBouncyCastleProvider()
    val trustStore = KeyStore.getInstance(KEYSTORE_TYPE, BouncyCastleProvider.PROVIDER_NAME)
    trustStore.load(null, null)
    trustStore.setCertificateEntry(CA_CERT_ALIAS, caBundle.certificate)

    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(trustStore)

    val sslContext = SSLContext.getInstance(SSL_PROTOCOL)
    sslContext.init(null, tmf.trustManagers, null)
    return sslContext
}
