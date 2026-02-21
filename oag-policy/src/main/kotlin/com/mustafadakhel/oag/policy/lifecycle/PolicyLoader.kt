package com.mustafadakhel.oag.policy.lifecycle

import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.distribution.decodeFromPath
import com.mustafadakhel.oag.policy.validation.PolicyValidationException
import com.mustafadakhel.oag.policy.validation.validatePolicy

import java.nio.file.Files
import java.nio.file.Path

private const val MAX_INCLUDE_DEPTH = 3

fun loadPolicy(path: Path): PolicyDocument = decodeFromPath(path)

fun loadAndValidatePolicy(path: Path): PolicyDocument {
    val resolved = resolveIncludes(path)
    val errors = validatePolicy(resolved)
    if (errors.isNotEmpty()) {
        throw PolicyValidationException(errors)
    }
    return resolved
}

fun resolveIncludes(path: Path): PolicyDocument {
    val canonical = path.toAbsolutePath().normalize()
    return resolveIncludesRecursive(canonical, mutableSetOf(), 0)
}

private fun resolveIncludesRecursive(
    path: Path,
    visited: MutableSet<Path>,
    depth: Int
): PolicyDocument {
    if (depth > MAX_INCLUDE_DEPTH) {
        throw PolicyIncludeException("Include depth exceeds maximum of $MAX_INCLUDE_DEPTH at $path")
    }
    val canonical = path.toAbsolutePath().normalize()
    if (!visited.add(canonical)) {
        throw PolicyIncludeException("Circular include detected: $canonical")
    }
    val policy = loadPolicy(canonical)
    if (policy.includes.isNullOrEmpty()) {
        return policy
    }
    val parentDir = canonical.parent ?: throw PolicyIncludeException("Cannot resolve parent directory for $canonical")
    val included = policy.includes.map { includePath ->
        val candidatePath = parentDir.resolve(includePath).toAbsolutePath().normalize()
        if (!Files.exists(candidatePath)) {
            throw PolicyIncludeException("Included policy file not found: $includePath (resolved to $candidatePath)")
        }
        val resolvedPath = candidatePath.toRealPath()
        val realParentDir = parentDir.toRealPath()
        if (!resolvedPath.startsWith(realParentDir)) {
            throw PolicyIncludeException("Include path escapes policy directory: $includePath")
        }
        resolveIncludesRecursive(resolvedPath, visited, depth + 1)
    }
    val mergedAllow = policy.allow.orEmpty() + included.flatMap { it.allow.orEmpty() }
    val mergedDeny = policy.deny.orEmpty() + included.flatMap { it.deny.orEmpty() }
    val mergedSecretScopes = policy.secretScopes.orEmpty() + included.flatMap { it.secretScopes.orEmpty() }
    val mergedAgentProfiles = policy.agentProfiles.orEmpty() + included.flatMap { it.agentProfiles.orEmpty() }
    return policy.copy(
        includes = null,
        allow = mergedAllow.ifEmpty { null },
        deny = mergedDeny.ifEmpty { null },
        secretScopes = mergedSecretScopes.ifEmpty { null },
        agentProfiles = mergedAgentProfiles.ifEmpty { null }
    )
}

class PolicyIncludeException(message: String) : RuntimeException(message)
