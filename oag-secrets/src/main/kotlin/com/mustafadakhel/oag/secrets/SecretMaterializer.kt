package com.mustafadakhel.oag.secrets

data class SecretInjectionResult(
    val attemptedIds: List<String>,
    val injected: Boolean,
    val secretIds: List<String>,
    val errors: List<String>,
    val secretVersions: Map<String, String> = emptyMap()
)

data class SecretInjectionOutcome(
    val headers: Map<String, String>,
    val result: SecretInjectionResult
)

class SecretMaterializer(
    private val provider: SecretProvider
) {
    private data class InjectionAccumulator(
        val headers: Map<String, String> = emptyMap(),
        val injectedIds: List<String> = emptyList(),
        val attemptedIds: List<String> = emptyList(),
        val errors: List<String> = emptyList(),
        val versions: Map<String, String> = emptyMap()
    )

    fun inject(
        headers: Map<String, String>,
        allowedSecretIds: Set<String>
    ): SecretInjectionOutcome {
        val normalizedAllowed = allowedSecretIds.map { it.trim() }.filter { it.isNotEmpty() }.toSet()

        val result = headers.keys.toList().fold(InjectionAccumulator(headers = headers)) { acc, header ->
            val value = acc.headers[header] ?: return@fold acc
            val placeholder = parseSecretPlaceholder(value)
            if (placeholder == null) {
                if (value.contains(SECRET_PLACEHOLDER_PREFIX)) {
                    val remainder = value.substringAfter(SECRET_PLACEHOLDER_PREFIX).trim()
                    val id = if (remainder.isEmpty()) "<empty>" else remainder
                    return@fold acc.copy(
                        attemptedIds = acc.attemptedIds + id,
                        errors = acc.errors + "secret_invalid_id:$id"
                    )
                }
                return@fold acc
            }

            val secretId = placeholder.secretId
            val effectiveId = if (secretId.isBlank()) "<empty>" else secretId
            val withAttempt = acc.copy(attemptedIds = acc.attemptedIds + effectiveId)

            if (!secretId.isValidSecretId()) {
                return@fold withAttempt.copy(errors = withAttempt.errors + "secret_invalid_id:$effectiveId")
            }
            if (!normalizedAllowed.contains(secretId)) {
                return@fold withAttempt.copy(errors = withAttempt.errors + "secret_not_allowed:$secretId")
            }

            val resolved = provider.resolve(secretId)
                ?: return@fold withAttempt.copy(errors = withAttempt.errors + "secret_missing:$secretId")

            val newValue = if (placeholder.bearer) "$BEARER_SCHEME ${resolved.value}" else resolved.value
            withAttempt.copy(
                headers = withAttempt.headers + (header to newValue),
                injectedIds = withAttempt.injectedIds + secretId,
                versions = resolved.version?.let { withAttempt.versions + (secretId to it) } ?: withAttempt.versions
            )
        }

        return SecretInjectionOutcome(
            headers = result.headers,
            result = SecretInjectionResult(
                attemptedIds = result.attemptedIds,
                injected = result.injectedIds.isNotEmpty() && result.errors.isEmpty(),
                secretIds = result.injectedIds,
                errors = result.errors,
                secretVersions = result.versions
            )
        )
    }
}

private fun String.isValidSecretId(): Boolean =
    isNotBlank() && none { it.isWhitespace() }
