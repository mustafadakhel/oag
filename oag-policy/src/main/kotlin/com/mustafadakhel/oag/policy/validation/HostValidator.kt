package com.mustafadakhel.oag.policy.validation

internal fun validateHost(base: String, host: String): List<ValidationError> = buildList {
    val trimmedHost = host.trim()
    if (trimmedHost.any(Char::isWhitespace)) {
        add(ValidationError(base, "Host must not contain whitespace"))
        return@buildList
    }
    if (trimmedHost.contains("://") || trimmedHost.contains("/")) {
        add(ValidationError(base, "Host must not include scheme or path"))
        return@buildList
    }
    if (trimmedHost.contains(":")) {
        add(ValidationError(base, "Host must not include port"))
        return@buildList
    }
    if (trimmedHost.startsWith(".")) {
        add(ValidationError(base, "Host must not start with '.'"))
        return@buildList
    }
    if (trimmedHost.contains("..")) {
        add(ValidationError(base, "Host must not contain consecutive dots"))
        return@buildList
    }
    if (trimmedHost.trimEnd('.').isEmpty()) {
        add(ValidationError(base, "Host must not be empty"))
        return@buildList
    }

    if (trimmedHost.contains("*")) {
        if (!trimmedHost.startsWith("*.") || trimmedHost.count { it == '*' } > 1) {
            add(ValidationError(base, "Wildcard host must be in the form '*.example.com'"))
            return@buildList
        }
        val suffix = trimmedHost.removePrefix("*.")
        if (suffix.isBlank() || suffix.startsWith(".") || suffix.endsWith(".") || suffix.contains("..") || suffix.contains("*")) {
            add(ValidationError(base, "Wildcard host must include a valid suffix"))
        }
    }
}

internal fun List<String>?.validateHosts(base: String): List<ValidationError> = buildList {
    val seen = mutableSetOf<String>()
    this@validateHosts?.forEachIndexed { index, value ->
        val trimmed = value.trim()
        when {
            trimmed.isEmpty() -> add(ValidationError("$base[$index]", "Empty host"))
            !seen.add(trimmed) -> add(ValidationError("$base[$index]", "Duplicate host '$trimmed'"))
            else -> validateHost("$base[$index]", trimmed).forEach { add(it) }
        }
    }
}
