package com.mustafadakhel.oag.policy.lifecycle

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.HEADER_USER_AGENT
import com.mustafadakhel.oag.HTTP_SUCCESS_RANGE
import com.mustafadakhel.oag.METHOD_GET
import com.mustafadakhel.oag.SCHEME_HTTP
import com.mustafadakhel.oag.SCHEME_HTTPS

import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.distribution.policyYaml

import java.net.HttpURLConnection
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

private const val POLICY_FETCHER_USER_AGENT = "oag-policy-fetcher/1.0"

data class PolicyFetchConfig(
    val url: String,
    val intervalSeconds: Long = 60,
    val timeoutMs: Int = 10_000,
    val cachePath: Path
)

data class PolicyFetchResult(
    val changed: Boolean,
    val contentHash: String,
    val bytesDownloaded: Int
)

class PolicyFetcher(
    private val config: PolicyFetchConfig,
    private val debugLog: ((String) -> Unit)? = null
) {
    private var lastContentHash: String? = null

    @Synchronized
    fun fetch(): PolicyFetchResult {
        val uri = URI(config.url)
        require(uri.scheme in ALLOWED_SCHEMES) { "Unsupported policy fetch URL scheme '${uri.scheme}': only http and https are allowed" }
        val conn = (uri.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = METHOD_GET
            connectTimeout = config.timeoutMs
            readTimeout = config.timeoutMs
            instanceFollowRedirects = false
            setRequestProperty(HEADER_USER_AGENT, POLICY_FETCHER_USER_AGENT)
        }

        try {
            val responseCode = conn.responseCode
            if (responseCode !in HTTP_SUCCESS_RANGE) {
                throw PolicyFetchException("HTTP $responseCode from ${config.url}")
            }

            val body = conn.inputStream.use { it.readNBytes(MAX_POLICY_BYTES + 1) }
            if (body.size > MAX_POLICY_BYTES) {
                throw PolicyFetchException("Policy response exceeds ${MAX_POLICY_BYTES} bytes from ${config.url}")
            }
            val contentHash = sha256Hex(body)

            if (contentHash == lastContentHash) {
                debugLog?.invoke("policy fetch unchanged hash=$contentHash")
                return PolicyFetchResult(changed = false, contentHash = contentHash, bytesDownloaded = body.size)
            }

            val bodyText = body.toString(Charsets.UTF_8)
            runCatching { policyYaml.decodeFromString(PolicyDocument.serializer(), bodyText) }
                .onFailure { e -> throw PolicyFetchException("Fetched content is not valid policy YAML: ${e.message}") }

            val cacheDir = config.cachePath.parent ?: config.cachePath.toAbsolutePath().parent
            cacheDir?.let { Files.createDirectories(it) }
            val tmpFile = Files.createTempFile(cacheDir, ".oag-policy-", ".tmp")
            try {
                Files.write(tmpFile, body)
                Files.move(tmpFile, config.cachePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (e: Exception) {
                Files.deleteIfExists(tmpFile)
                throw e
            }
            lastContentHash = contentHash
            debugLog?.invoke("policy fetched and cached hash=$contentHash bytes=${body.size}")
            return PolicyFetchResult(changed = true, contentHash = contentHash, bytesDownloaded = body.size)
        } finally {
            conn.disconnect()
        }
    }

    companion object {
        const val MAX_POLICY_BYTES = 10 * 1024 * 1024 // 10 MB
        private val ALLOWED_SCHEMES = setOf(SCHEME_HTTP, SCHEME_HTTPS)
    }

    private fun sha256Hex(data: ByteArray): String {
        val digest = MessageDigest.getInstance(CryptoConstants.SHA_256)
        return digest.digest(data).toHexString()
    }
}

class PolicyFetchException(message: String) : RuntimeException(message)
