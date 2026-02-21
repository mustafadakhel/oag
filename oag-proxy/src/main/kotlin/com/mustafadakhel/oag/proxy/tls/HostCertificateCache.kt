package com.mustafadakhel.oag.proxy.tls

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.MS_PER_DAY

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap

private const val HOST_KEY_SIZE = 2048
private const val HOST_VALIDITY_DAYS = 30L
private val HOST_SIGNATURE_ALGORITHM = CryptoConstants.SHA256_WITH_RSA
private const val DEFAULT_MAX_CACHE_SIZE = 1000

data class HostCertificate(
    val certificate: X509Certificate,
    val keyPair: KeyPair
)

class HostCertificateCache(
    private val caBundle: CaBundle,
    private val maxCacheSize: Int = DEFAULT_MAX_CACHE_SIZE,
    private val keySizeBits: Int = HOST_KEY_SIZE,
    private val validityDays: Long = HOST_VALIDITY_DAYS
) {
    private val cache = ConcurrentHashMap<String, HostCertificate>()
    private val lock = Any()
    private val secureRandom = SecureRandom()

    val size: Int get() = cache.size

    fun getOrCreate(hostname: String): HostCertificate {
        synchronized(lock) { evictIfNeeded() }
        // ConcurrentHashMap.compute() is atomic per-key: only one thread generates
        // a certificate for a given hostname. Key generation happens outside the global lock.
        return cache.compute(hostname) { _, existing ->
            if (existing != null && isValid(existing.certificate)) existing
            else generateHostCertificate(hostname)
        }!!
    }

    fun evict(hostname: String) {
        cache.remove(hostname)
    }

    fun clear() {
        cache.clear()
    }

    private fun isValid(cert: X509Certificate): Boolean =
        runCatching { cert.checkValidity(); true }.getOrDefault(false)

    private fun evictIfNeeded() {
        if (cache.size >= maxCacheSize) {
            val expired = cache.entries.filterNot { isValid(it.value.certificate) }
            if (expired.isNotEmpty()) {
                expired.forEach { cache.remove(it.key) }
            } else {
                val oldest = cache.entries.minByOrNull { it.value.certificate.notAfter.time }
                oldest?.let { cache.remove(it.key) }
            }
        }
    }

    private fun generateHostCertificate(hostname: String): HostCertificate {
        val hostKeyPair = KeyPairGenerator.getInstance(CryptoConstants.RSA).run {
            initialize(keySizeBits, secureRandom)
            generateKeyPair()
        }

        val now = Date()
        val notAfter = Date(now.time + validityDays * MS_PER_DAY)
        val serial = BigInteger(128, secureRandom)

        val issuerName = X500Name(caBundle.certificate.subjectX500Principal.name)
        // Escape special characters per RFC 4514 section 2.4 for safe embedding in X.500 DN strings.
        // Order matters: backslash must be escaped first to avoid double-escaping.
        // RFC 4514 section 2.4: escape special characters for safe embedding in X.500 DN strings.
        // Backslash first to avoid double-escaping subsequent replacements.
        val escapedHostname = hostname
            .replace("\\", "\\\\")
            .replace(",", "\\,")
            .replace("+", "\\+")
            .replace("\"", "\\\"")
            .replace("<", "\\<")
            .replace(">", "\\>")
            .replace(";", "\\;")
        val subjectName = X500Name("CN=$escapedHostname")

        val builder = JcaX509v3CertificateBuilder(
            issuerName, serial, now, notAfter, subjectName, hostKeyPair.public
        ).apply {
            addExtension(Extension.basicConstraints, false, BasicConstraints(false))
            addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment))
            addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, hostname)))
        }

        val signer = JcaContentSignerBuilder(HOST_SIGNATURE_ALGORITHM)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(caBundle.keyPair.private)

        val certificate = JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(signer))

        return HostCertificate(certificate = certificate, keyPair = hostKeyPair)
    }
}
