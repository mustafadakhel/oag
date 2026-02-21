package com.mustafadakhel.oag.secrets

internal const val SECRET_PLACEHOLDER_PREFIX = "OAG_PLACEHOLDER_"
internal const val BEARER_SCHEME = "Bearer"

private val WHITESPACE_REGEX = Regex("\\s+")

internal data class SecretPlaceholder(
    val secretId: String,
    val bearer: Boolean
)

internal fun parseSecretPlaceholder(value: String): SecretPlaceholder? {
    val trimmed = value.trim()
    val parts = trimmed.split(WHITESPACE_REGEX)
    return when {
        parts.size == 1 && parts[0].startsWith(SECRET_PLACEHOLDER_PREFIX) ->
            SecretPlaceholder(parts[0].removePrefix(SECRET_PLACEHOLDER_PREFIX), bearer = false)
        parts.size == 2 && parts[0].equals(BEARER_SCHEME, ignoreCase = true) && parts[1].startsWith(SECRET_PLACEHOLDER_PREFIX) ->
            SecretPlaceholder(parts[1].removePrefix(SECRET_PLACEHOLDER_PREFIX), bearer = true)
        else -> null
    }
}
