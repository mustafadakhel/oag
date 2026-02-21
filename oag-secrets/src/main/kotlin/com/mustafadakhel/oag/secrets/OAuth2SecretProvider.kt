package com.mustafadakhel.oag.secrets

import com.mustafadakhel.oag.HTTP_SUCCESS_RANGE
import com.mustafadakhel.oag.CONTENT_TYPE_FORM_URLENCODED
import com.mustafadakhel.oag.HEADER_CONTENT_TYPE
import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.METHOD_POST
import com.mustafadakhel.oag.MS_PER_SECOND
import com.mustafadakhel.oag.RetryExhaustedException
import com.mustafadakhel.oag.RetryPolicy
import com.mustafadakhel.oag.withRetry

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.time.Clock

class OAuth2SecretProvider(
    private val tokenUrl: String,
    private val clientId: String,
    private val clientSecret: String,
    private val scope: String? = null,
    private val timeoutMs: Int = DEFAULT_TIMEOUT_MS,
    private val refreshMarginMs: Long = DEFAULT_REFRESH_MARGIN_MS,
    private val maxRetries: Int = DEFAULT_MAX_RETRIES,
    private val initialBackoffMs: Long = DEFAULT_INITIAL_BACKOFF_MS,
    private val defaultExpirySeconds: Long = DEFAULT_EXPIRY_SECONDS,
    private val clock: Clock = Clock.systemUTC(),
    private val onError: (String) -> Unit = System.err::println
) : SecretProvider {

    private val lock = Any()
    private val safeTokenUrl: String = runCatching { URI(tokenUrl).let { uri ->
        URI(uri.scheme, null, uri.host, uri.port, uri.path, uri.query, null).toString()
    } }.getOrDefault(tokenUrl)
    @Volatile private var cachedToken: CachedToken? = null

    override fun resolve(secretId: String): SecretValue? {
        val token = currentToken() ?: return null
        return SecretValue(value = token.accessToken, version = null)
    }

    private fun currentToken(): CachedToken? {
        val existing = cachedToken
        if (existing != null && !existing.isExpired(refreshMarginMs, clock.millis())) return existing
        return synchronized(lock) {
            val rechecked = cachedToken
            if (rechecked != null && !rechecked.isExpired(refreshMarginMs, clock.millis())) return rechecked
            val fetched = fetchTokenWithRetry()
            cachedToken = fetched
            fetched
        }
    }

    // Uses blocking withRetry (Thread.sleep) because SecretProvider.resolve() is non-suspend.
    // The blocking sleep is acceptable here: token fetch runs during request processing on the
    // proxy thread pool, and the retry delay (typically <1s) is bounded by RetryPolicy.
    private fun fetchTokenWithRetry(): CachedToken? = try {
        withRetry(
            RetryPolicy(maxAttempts = maxRetries + 1, baseDelayMs = initialBackoffMs),
            onFailure = { attempt, _ ->
                onError("${LOG_PREFIX}oauth2 token fetch retry attempt=$attempt/${maxRetries + 1}")
            }
        ) {
            fetchToken() ?: throw TokenFetchException()
        }
    } catch (_: RetryExhaustedException) {
        null
    }

    private class TokenFetchException : Exception("token fetch returned null")

    private fun fetchToken(): CachedToken? {
        val body = buildString {
            append(OAuth2Constants.GRANT_TYPE_CLIENT_CREDENTIALS)
            append(OAuth2Constants.PARAM_CLIENT_ID).append(urlEncode(clientId))
            append(OAuth2Constants.PARAM_CLIENT_SECRET).append(urlEncode(clientSecret))
            if (!scope.isNullOrBlank()) append(OAuth2Constants.PARAM_SCOPE).append(urlEncode(scope))
        }
        val bodyBytes = body.toByteArray(Charsets.UTF_8)

        val conn = URI(tokenUrl).toURL().openConnection() as HttpURLConnection
        return try {
            conn.apply {
                requestMethod = METHOD_POST
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                doOutput = true
                setRequestProperty(HEADER_CONTENT_TYPE, CONTENT_TYPE_FORM_URLENCODED)
            }
            conn.outputStream.use { it.write(bodyBytes) }

            val responseCode = conn.responseCode
            if (responseCode !in HTTP_SUCCESS_RANGE) {
                val errorBody = runCatching { conn.errorStream?.use { it.readBytes()?.toString(Charsets.UTF_8) } }.getOrNull()
                onError("${LOG_PREFIX}oauth2 token fetch failed url=$safeTokenUrl status=$responseCode body=$errorBody")
                null
            } else {
                val responseBody = conn.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
                parseTokenResponse(responseBody)
            }
        } catch (e: IOException) {
            onError("${LOG_PREFIX}oauth2 token fetch failed url=$safeTokenUrl: ${e.message}")
            null
        } finally {
            conn.disconnect()
        }
    }

    internal fun parseTokenResponse(json: String): CachedToken? {
        val response = runCatching { jsonParser.decodeFromString<OAuth2TokenResponse>(json) }.getOrElse { e ->
            onError("${LOG_PREFIX}oauth2 token response parse failed url=$safeTokenUrl: ${e.message}")
            return null
        }
        val accessToken = response.accessToken
        if (accessToken == null) {
            onError("${LOG_PREFIX}oauth2 token response missing access_token url=$safeTokenUrl")
            return null
        }
        val expiresAtMs = response.expiresIn?.let { clock.millis() + it * MS_PER_SECOND }
            ?: (clock.millis() + defaultExpirySeconds * MS_PER_SECOND)
        return CachedToken(accessToken = accessToken, expiresAtMs = expiresAtMs)
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 10_000
        const val DEFAULT_REFRESH_MARGIN_MS = 30_000L
        const val DEFAULT_MAX_RETRIES = 2
        const val DEFAULT_INITIAL_BACKOFF_MS = 500L
        const val DEFAULT_EXPIRY_SECONDS = 3600L

        private val jsonParser = Json { ignoreUnknownKeys = true }

        private fun urlEncode(value: String): String =
            URLEncoder.encode(value, Charsets.UTF_8)
    }
}

@Serializable
internal data class OAuth2TokenResponse(
    @SerialName("access_token") val accessToken: String? = null,
    @SerialName("expires_in") val expiresIn: Long? = null
)

internal data class CachedToken(
    val accessToken: String,
    val expiresAtMs: Long
) {
    fun isExpired(marginMs: Long, nowMs: Long): Boolean =
        nowMs + marginMs >= expiresAtMs

    override fun toString(): String =
        "CachedToken(accessToken=REDACTED, expiresAtMs=$expiresAtMs)"
}
