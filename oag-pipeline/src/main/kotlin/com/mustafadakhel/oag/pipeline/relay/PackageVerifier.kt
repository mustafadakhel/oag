package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.ConcurrentLruMap
import com.mustafadakhel.oag.OutboundResult
import com.mustafadakhel.oag.SafeOutboundClient

import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse

enum class PackageStatus {
    EXISTS,
    NOT_FOUND,
    UNKNOWN
}

data class PackageVerificationResult(
    val registry: String,
    val packageName: String,
    val status: PackageStatus
)

class PackageVerifier(
    private val client: SafeOutboundClient,
    private val pypiMirror: String = DEFAULT_PYPI_REGISTRY,
    private val npmMirror: String = DEFAULT_NPM_REGISTRY,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    cacheCapacity: Int = DEFAULT_CACHE_CAPACITY
) {
    private val cache = ConcurrentLruMap<String, PackageStatus>(cacheCapacity)

    fun extractAndVerify(text: String): List<PackageVerificationResult> {
        val packages = extractPackageNames(text)
        return packages.mapNotNull { (registry, name) -> verifyOne(registry, name) }
    }

    private fun verifyOne(registry: String, name: String): PackageVerificationResult? {
        val cacheKey = "$registry:$name"
        cache.get(cacheKey)?.let { return PackageVerificationResult(registry, name, it) }

        val url = when (registry) {
            REGISTRY_PYPI -> "$pypiMirror/pypi/$name/json"
            REGISTRY_NPM -> "$npmMirror/$name"
            else -> return null
        }

        val request = runCatching {
            HttpRequest.newBuilder(URI(url))
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .build()
        }.getOrNull() ?: return PackageVerificationResult(registry, name, PackageStatus.UNKNOWN)

        val status = when (val result = client.execute(request, HttpResponse.BodyHandlers.discarding(), timeoutMs)) {
            is OutboundResult.Blocked -> PackageStatus.UNKNOWN
            is OutboundResult.Failure -> PackageStatus.UNKNOWN
            is OutboundResult.Success -> when (result.value.statusCode()) {
                in HTTP_SUCCESS_RANGE -> PackageStatus.EXISTS
                HTTP_NOT_FOUND -> PackageStatus.NOT_FOUND
                else -> PackageStatus.UNKNOWN
            }
        }

        cache.put(cacheKey, status)
        return PackageVerificationResult(registry, name, status)
    }

    companion object {
        const val REGISTRY_PYPI = "pypi"
        const val REGISTRY_NPM = "npm"
        private const val DEFAULT_PYPI_REGISTRY = "https://pypi.org"
        private const val DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org"
        private const val DEFAULT_TIMEOUT_MS = 3_000L
        private const val DEFAULT_CACHE_CAPACITY = 256
        private val HTTP_SUCCESS_RANGE = 200..299
        private const val HTTP_NOT_FOUND = 404
    }
}

internal data class PackageReference(val registry: String, val name: String)

private val PIP_INSTALL_PATTERN = Regex("""pip3?\s+install\s+([a-zA-Z0-9_-][a-zA-Z0-9._-]*)""")
private val IMPORT_PATTERN = Regex("""(?:from|import)\s+([a-zA-Z_][a-zA-Z0-9_]*)""")
private val NPM_INSTALL_PATTERN = Regex("""npm\s+(?:install|i)\s+(?:--save(?:-dev)?\s+)?([a-zA-Z@][a-zA-Z0-9./_-]*)""")
private val REQUIRE_PATTERN = Regex("""require\(\s*['"]([a-zA-Z@][a-zA-Z0-9./_-]*)['"]""")

private val PYTHON_STDLIB = setOf(
    "os", "sys", "re", "json", "math", "time", "datetime", "collections",
    "itertools", "functools", "pathlib", "typing", "io", "abc", "copy",
    "logging", "unittest", "argparse", "subprocess", "threading", "socket",
    "http", "urllib", "hashlib", "base64", "csv", "xml", "html", "string",
    "random", "struct", "enum", "dataclasses", "contextlib", "textwrap",
    "shutil", "tempfile", "glob", "fnmatch", "stat", "gzip", "zipfile",
    "tarfile", "pickle", "shelve", "sqlite3", "email", "ssl", "asyncio",
    "concurrent", "multiprocessing", "signal", "platform", "traceback",
    "warnings", "inspect", "dis", "pdb", "profile", "pstats", "timeit",
    "builtins", "types", "weakref", "array", "queue", "heapq", "bisect",
    "decimal", "fractions", "statistics", "secrets", "uuid", "pprint"
)

internal fun extractPackageNames(text: String): List<PackageReference> {
    val packages = mutableSetOf<PackageReference>()

    PIP_INSTALL_PATTERN.findAll(text).forEach { match ->
        val name = match.groupValues[1]
        if (name.length > 1) packages.add(PackageReference(PackageVerifier.REGISTRY_PYPI, name))
    }

    IMPORT_PATTERN.findAll(text).forEach { match ->
        val name = match.groupValues[1]
        if (name.length > 1 && name !in PYTHON_STDLIB && name[0].isLowerCase()) {
            packages.add(PackageReference(PackageVerifier.REGISTRY_PYPI, name))
        }
    }

    NPM_INSTALL_PATTERN.findAll(text).forEach { match ->
        val name = match.groupValues[1]
        if (name.length > 1) packages.add(PackageReference(PackageVerifier.REGISTRY_NPM, name))
    }

    REQUIRE_PATTERN.findAll(text).forEach { match ->
        val name = match.groupValues[1]
        if (name.length > 1 && !name.startsWith(".")) {
            packages.add(PackageReference(PackageVerifier.REGISTRY_NPM, name))
        }
    }

    return packages.take(MAX_PACKAGES_PER_RESPONSE).toList()
}

private const val MAX_PACKAGES_PER_RESPONSE = 10
