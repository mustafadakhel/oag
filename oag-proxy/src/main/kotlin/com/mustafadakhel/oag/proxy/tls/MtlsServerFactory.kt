package com.mustafadakhel.oag.proxy.tls

import com.mustafadakhel.oag.CryptoConstants

import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocketFactory
import javax.net.ssl.TrustManagerFactory

internal fun buildMtlsServerSocketFactory(
    keystorePath: String,
    keystorePassword: String?,
    caCertPath: String
): SSLServerSocketFactory {
    val passwordChars = keystorePassword?.toCharArray() ?: charArrayOf()
    try {
        val keyStore = KeyStore.getInstance(CryptoConstants.KEYSTORE_PKCS12)
        FileInputStream(keystorePath).use { keyStore.load(it, passwordChars) }
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, passwordChars)

        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
        trustStore.load(null, null)
        val certFactory = CertificateFactory.getInstance(CryptoConstants.CERT_X509)
        FileInputStream(caCertPath).use { inputStream ->
            val certs = certFactory.generateCertificates(inputStream)
            certs.forEachIndexed { index, cert ->
                trustStore.setCertificateEntry("client-ca-$index", cert)
            }
        }
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(trustStore)

        val sslContext = SSLContext.getInstance(CryptoConstants.TLS)
        sslContext.init(
            keyManagerFactory.keyManagers,
            trustManagerFactory.trustManagers,
            null
        )
        return sslContext.serverSocketFactory
    } finally {
        passwordChars.fill('\u0000')
    }
}
