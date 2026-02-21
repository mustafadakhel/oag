package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.support.parseIpRange

import java.util.Locale

internal fun List<String>?.validateMethods(validMethods: Set<String>, base: String): List<ValidationError> = buildList {
    val seen = mutableSetOf<String>()
    this@validateMethods?.forEachIndexed { index, method ->
        when {
            method.isBlank() -> add(ValidationError("$base[$index]", "Empty method"))
            else -> {
                if (method.any(Char::isWhitespace)) {
                    add(ValidationError("$base[$index]", "Method must not contain whitespace"))
                    return@forEachIndexed
                }
                val normalized = method.trim().uppercase(Locale.ROOT)
                if (!validMethods.contains(normalized)) {
                    add(ValidationError("$base[$index]", "Unsupported method '$method'"))
                } else if (!seen.add(normalized)) {
                    add(ValidationError("$base[$index]", "Duplicate method '$normalized'"))
                }
            }
        }
    }
}

internal fun List<String>?.validatePaths(base: String): List<ValidationError> = buildList {
    val seen = mutableSetOf<String>()
    this@validatePaths?.forEachIndexed { index, value ->
        val path = value.trim()
        when {
            path.isEmpty() -> add(ValidationError("$base[$index]", "Empty path"))
            path.any(Char::isWhitespace) -> add(ValidationError("$base[$index]", "Path must not contain whitespace"))
            !(path.startsWith("/") || path.startsWith("*")) -> add(ValidationError("$base[$index]", "Path must start with '/' or '*'"))
            path.contains("://") -> add(ValidationError("$base[$index]", "Path must not include scheme or host"))
            !seen.add(path) -> add(ValidationError("$base[$index]", "Duplicate path '$path'"))
        }
    }
}

internal fun List<String>?.validateSecrets(base: String): List<ValidationError> = buildList {
    val seen = mutableSetOf<String>()
    this@validateSecrets?.forEachIndexed { index, value ->
        when {
            value.isBlank() -> add(ValidationError("$base[$index]", "Empty secret id"))
            value.any(Char::isWhitespace) -> add(ValidationError("$base[$index]", "Secret id must not contain whitespace"))
            !seen.add(value.trim()) -> add(ValidationError("$base[$index]", "Duplicate secret id '${value.trim()}'"))
        }
    }
}

internal fun List<String>?.validateIpRanges(base: String): List<ValidationError> = buildList {
    val seen = mutableSetOf<String>()
    this@validateIpRanges?.forEachIndexed { index, value ->
        val trimmed = value.trim()
        when {
            trimmed.isEmpty() -> add(ValidationError("$base[$index]", "Empty ip range"))
            trimmed.any(Char::isWhitespace) -> add(ValidationError("$base[$index]", "IP range must not contain whitespace"))
            !seen.add(trimmed) -> add(ValidationError("$base[$index]", "Duplicate ip range '$trimmed'"))
            else -> runCatching { parseIpRange(trimmed) }.getOrElse {
                add(ValidationError("$base[$index]", "Invalid ip range '$trimmed'"))
            }
        }
    }
}
