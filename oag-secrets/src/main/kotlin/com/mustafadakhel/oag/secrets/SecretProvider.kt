package com.mustafadakhel.oag.secrets

import com.mustafadakhel.oag.REDACTED_SENTINEL

import java.nio.file.Files
import java.nio.file.Path

interface SecretProvider {
    fun resolve(secretId: String): SecretValue?
}

data class SecretValue(
    val value: String,
    val version: String? = null
) {
    override fun toString(): String = "SecretValue(value=$REDACTED_SENTINEL, version=$version)"
}

class EnvSecretProvider(
    private val prefix: String
) : SecretProvider {
    override fun resolve(secretId: String): SecretValue? {
        val key = prefix + secretId
        val value = System.getenv(key) ?: return null
        return SecretValue(value = value, version = System.getenv("${key}_VERSION"))
    }
}

class FileSecretProvider(
    private val directory: Path,
    private val suffix: String = SECRET_FILE_SUFFIX
) : SecretProvider {
    override fun resolve(secretId: String): SecretValue? {
        val file = directory.resolve("$secretId$suffix").normalize()
        if (!file.startsWith(directory.normalize())) return null
        if (!Files.exists(file)) return null
        // Resolve symlinks to prevent traversal via symlink chains
        val realFile = file.toRealPath()
        val realDir = directory.toRealPath()
        if (!realFile.startsWith(realDir)) return null
        val value = Files.readString(realFile).trimEnd()
        if (value.isEmpty()) return null
        val versionFile = directory.resolve("$secretId$suffix$VERSION_FILE_SUFFIX").normalize()
        val version = if (Files.exists(versionFile)) {
            Files.readString(versionFile).trim().ifEmpty { null }
        } else {
            null
        }
        return SecretValue(value = value, version = version)
    }

    companion object {
        const val SECRET_FILE_SUFFIX = ".secret"
        const val VERSION_FILE_SUFFIX = ".version"
    }
}
