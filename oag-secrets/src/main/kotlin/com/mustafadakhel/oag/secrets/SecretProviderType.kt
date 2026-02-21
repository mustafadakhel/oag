package com.mustafadakhel.oag.secrets

import com.mustafadakhel.oag.REDACTED_SENTINEL
import com.mustafadakhel.oag.label

import java.nio.file.Path
import java.util.Locale

enum class SecretProviderType {
    ENV,
    FILE,
    OAUTH2;

    companion object {
        fun from(raw: String?): SecretProviderType? =
            raw?.let { value ->
                entries.firstOrNull { it.label() == value.trim().lowercase(Locale.ROOT) }
            }
    }
}

data class SecretProviderConfig(
    val envPrefix: String = "",
    val fileDir: String? = null,
    val oauth2TokenUrl: String? = null,
    val oauth2ClientId: String? = null,
    val oauth2ClientSecret: String? = null,
    val oauth2Scope: String? = null
) {
    override fun toString(): String =
        "SecretProviderConfig(envPrefix=$envPrefix, fileDir=$fileDir, oauth2TokenUrl=$oauth2TokenUrl, " +
            "oauth2ClientId=$oauth2ClientId, oauth2ClientSecret=${REDACTED_SENTINEL}, oauth2Scope=$oauth2Scope)"
}

fun buildSecretProvider(type: SecretProviderType, config: SecretProviderConfig): SecretProvider =
    when (type) {
        SecretProviderType.ENV -> EnvSecretProvider(config.envPrefix)
        SecretProviderType.FILE -> {
            val dir = requireNotNull(config.fileDir) { "fileDir must be set when secretProvider is file" }
            FileSecretProvider(Path.of(dir))
        }
        SecretProviderType.OAUTH2 -> {
            val tokenUrl = requireNotNull(config.oauth2TokenUrl) { "oauth2TokenUrl must be set when secretProvider is oauth2" }
            val clientId = requireNotNull(config.oauth2ClientId) { "oauth2ClientId must be set when secretProvider is oauth2" }
            val clientSecret = requireNotNull(config.oauth2ClientSecret) { "oauth2ClientSecret must be set when secretProvider is oauth2" }
            OAuth2SecretProvider(
                tokenUrl = tokenUrl,
                clientId = clientId,
                clientSecret = clientSecret,
                scope = config.oauth2Scope
            )
        }
    }
