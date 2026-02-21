package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.SecretScope

internal fun validateSecretScopes(scopes: List<SecretScope>?): List<ValidationError> =
    scopes.orEmpty().flatMapIndexed { index, scope ->
        scope.validate("secret_scopes[$index]", VALID_METHODS)
    }

internal fun SecretScope.validate(base: String, validMethods: Set<String>): List<ValidationError> = buildList {
    if (id.isNullOrBlank()) {
        add(ValidationError("$base.id", "Missing or empty"))
    } else if (id.any(Char::isWhitespace)) {
        add(ValidationError("$base.id", "Secret scope id must not contain whitespace"))
    }
    if (hosts.isNullOrEmpty() && ipRanges.isNullOrEmpty()) {
        add(ValidationError("$base.hosts", "Secret scope must define hosts or ip ranges"))
    }
    hosts.validateHosts("$base.hosts").forEach { add(it) }
    methods.validateMethods(validMethods, "$base.methods").forEach { add(it) }
    paths.validatePaths("$base.paths").forEach { add(it) }
    ipRanges.validateIpRanges("$base.ip_ranges").forEach { add(it) }
}
