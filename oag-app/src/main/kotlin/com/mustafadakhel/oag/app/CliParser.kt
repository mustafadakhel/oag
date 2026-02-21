package com.mustafadakhel.oag.app

import com.mustafadakhel.oag.SCHEME_HTTPS
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.http.parseAbsoluteTarget
import com.mustafadakhel.oag.secrets.SecretProviderType
import com.mustafadakhel.oag.telemetry.OtelConfig
import com.mustafadakhel.oag.telemetry.OtelExporterType

import java.nio.file.Files
import java.nio.file.Path

internal val REQUEST_SPEC_SPLIT_REGEX = Regex("\\s+")
internal const val DEFAULT_SCHEME = SCHEME_HTTPS
internal const val DEFAULT_PATH = "/"

internal fun parseRequestSpec(spec: String, errorContext: String): PolicyRequest {
    val parts = spec.trim().split(REQUEST_SPEC_SPLIT_REGEX, limit = 2)
    if (parts.size != 2) throw InvalidArgumentException.of(errorContext)
    val (rawMethod, rawTarget) = parts
    val method = rawMethod.trim()
    val target = parseAbsoluteTarget(rawTarget.trim())
    return PolicyRequest(
        scheme = target.scheme,
        host = target.host,
        port = target.port,
        method = method,
        path = target.path
    )
}

private val BOOLEAN_FLAGS = setOf(
    CliFlags.JSON, CliFlags.VERBOSE, CliFlags.DRY_RUN, CliFlags.WATCH,
    CliFlags.POLICY_REQUIRE_SIGNATURE, CliFlags.BLOCK_IP_LITERALS,
    CliFlags.ENFORCE_REDIRECT_POLICY, CliFlags.BLOCK_PRIVATE_RESOLVED_IPS,
    CliFlags.TLS_INSPECT, CliFlags.REQUIRE_SIGNED_HEADERS,
    CliFlags.INJECT_REQUEST_ID, CliFlags.LOG_COMPRESS, CliFlags.VERIFY
).map { it.removePrefix(CliFlags.FLAG_PREFIX) }.toSet()

internal val VALUE_FLAGS: Set<String> = setOf(
    CliFlags.POLICY, CliFlags.CONFIG_DIR, CliFlags.PORT, CliFlags.LOG,
    CliFlags.AGENT, CliFlags.SESSION, CliFlags.MAX_THREADS,
    CliFlags.POLICY_PUBLIC_KEY, CliFlags.SECRET_PREFIX, CliFlags.SECRET_PROVIDER,
    CliFlags.SECRET_DIR, CliFlags.OAUTH2_TOKEN_URL, CliFlags.OAUTH2_CLIENT_ID,
    CliFlags.OAUTH2_CLIENT_SECRET, CliFlags.OAUTH2_SCOPE,
    CliFlags.CONNECT_TIMEOUT_MS, CliFlags.READ_TIMEOUT_MS, CliFlags.DRAIN_TIMEOUT_MS,
    CliFlags.TLS_CA_CERT_PATH, CliFlags.MTLS_CA_CERT, CliFlags.MTLS_KEYSTORE,
    CliFlags.MTLS_KEYSTORE_PASSWORD, CliFlags.AGENT_SIGNING_SECRET,
    CliFlags.ADMIN_PORT, CliFlags.ADMIN_ALLOWED_IPS, CliFlags.ADMIN_TOKEN,
    CliFlags.ADMIN_RELOAD_COOLDOWN_MS,
    CliFlags.CIRCUIT_BREAKER_THRESHOLD, CliFlags.CIRCUIT_BREAKER_RESET_MS,
    CliFlags.CIRCUIT_BREAKER_HALF_OPEN_PROBES,
    CliFlags.REQUEST_ID_HEADER, CliFlags.POOL_MAX_IDLE, CliFlags.POOL_IDLE_TIMEOUT_MS,
    CliFlags.LOG_MAX_SIZE_MB, CliFlags.LOG_MAX_FILES, CliFlags.LOG_ROTATION_INTERVAL,
    CliFlags.WEBHOOK_URL, CliFlags.WEBHOOK_EVENTS, CliFlags.WEBHOOK_TIMEOUT_MS,
    CliFlags.WEBHOOK_SIGNING_SECRET, CliFlags.VELOCITY_SPIKE_THRESHOLD,
    CliFlags.POLICY_URL, CliFlags.POLICY_FETCH_INTERVAL_S, CliFlags.INTEGRITY_CHECK_INTERVAL_S,
    CliFlags.OTEL_EXPORTER, CliFlags.OTEL_ENDPOINT, CliFlags.OTEL_HEADERS,
    CliFlags.OTEL_TIMEOUT_MS, CliFlags.OTEL_SERVICE_NAME, CliFlags.PLUGIN_PROVIDER,
    CliFlags.METHOD, CliFlags.HOST, CliFlags.PATH, CliFlags.SCHEME, CliFlags.BATCH,
    CliFlags.CASES, CliFlags.REQUEST, CliFlags.OUT, CliFlags.SIGN_KEY, CliFlags.KEY_ID,
    CliFlags.BUNDLE, CliFlags.PUBLIC_KEY
).map { it.removePrefix(CliFlags.FLAG_PREFIX) }.toSet()

internal class ParsedArgs(args: Array<String>) {
    private val flags: Set<String>
    private val values: Map<String, String>
    val positional: List<String>

    init {
        val f = mutableSetOf<String>()
        val v = mutableMapOf<String, String>()
        val p = mutableListOf<String>()
        var i = 0
        while (i < args.size) {
            val token = args[i]
            if (token.startsWith(CliFlags.FLAG_PREFIX)) {
                val key = token.removePrefix(CliFlags.FLAG_PREFIX)
                if (key in VALUE_FLAGS) {
                    if (i + 1 >= args.size) throw MissingArgumentException.forFlag(token)
                    v[token] = args[i + 1]
                    i += 2
                } else {
                    f += token
                    i++
                }
            } else {
                p += token
                i++
            }
        }
        flags = f
        values = v
        positional = p
    }

    fun hasFlag(name: String): Boolean = name in flags
    fun value(name: String): String? = values[name]

    fun requireValue(name: String): String =
        value(name) ?: throw MissingArgumentException.forArgument(name)

    fun intValue(name: String, default: Int): Int =
        value(name)?.let { raw ->
            raw.toIntOrNull() ?: throw InvalidArgumentException.integer(name, raw)
        } ?: default

    fun longValue(name: String, default: Long): Long =
        value(name)?.let { raw ->
            raw.toLongOrNull() ?: throw InvalidArgumentException.number(name, raw)
        } ?: default

    fun doubleValue(name: String, default: Double): Double =
        value(name)?.let { raw ->
            raw.toDoubleOrNull() ?: throw InvalidArgumentException.number(name, raw)
        } ?: default

    fun optionalInt(name: String): Int? =
        value(name)?.let { raw ->
            raw.toIntOrNull() ?: throw InvalidArgumentException.integer(name, raw)
        }

    fun commaSeparatedList(name: String): List<String> =
        value(name)
            ?.split(",")
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?: emptyList()

    fun commaSeparatedSet(name: String): Set<String> =
        commaSeparatedList(name).toSet()
}

internal fun ParsedArgs.policyService(configDir: Path?, allowPositional: Boolean = true): PolicyService =
    PolicyService(
        policyPath = Path.of(resolvePolicyPath(configDir, allowPositional)),
        policyPublicKeyPath = value(CliFlags.POLICY_PUBLIC_KEY),
        requireSignature = hasFlag(CliFlags.POLICY_REQUIRE_SIGNATURE)
    )

internal fun ParsedArgs.configDirPath(): Path? {
    val raw = value(CliFlags.CONFIG_DIR) ?: return null
    val path = Path.of(raw)
    if (!Files.exists(path)) throw ConfigException("configDir does not exist: $raw")
    if (!Files.isDirectory(path)) throw ConfigException("configDir is not a directory: $raw")
    return path
}

internal fun ParsedArgs.resolvePolicyPath(configDir: Path?, allowPositional: Boolean): String {
    value(CliFlags.POLICY)?.let { return it }
    if (allowPositional) {
        positional.firstOrNull()?.let { return it }
    }
    configDir?.let { return it.resolve(CliDefaults.POLICY_FILE).toString() }
    throw MissingArgumentException.forArgument("${CliFlags.POLICY} (or ${CliFlags.CONFIG_DIR})")
}

internal fun ParsedArgs.parseSecretProvider(): SecretProviderType {
    val raw = value(CliFlags.SECRET_PROVIDER)
    val parsed = SecretProviderType.from(raw)
    if (raw != null && parsed == null) {
        throw InvalidArgumentException.value(CliFlags.SECRET_PROVIDER, raw)
    }
    return parsed ?: SecretProviderType.ENV
}

private fun ParsedArgs.parseOtelExporter(): OtelExporterType {
    val raw = value(CliFlags.OTEL_EXPORTER)
    val parsed = OtelExporterType.from(raw)
    if (raw != null && parsed == null) {
        throw InvalidArgumentException.value(CliFlags.OTEL_EXPORTER, raw)
    }
    return parsed ?: OtelExporterType.NONE
}

private fun ParsedArgs.parseOtelHeaders(): Map<String, String> {
    val raw = value(CliFlags.OTEL_HEADERS)?.trim().orEmpty()
    if (raw.isBlank()) return emptyMap()
    return raw.split(",")
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .associate { pair ->
            val parts = pair.split("=", limit = 2)
            if (parts.size != 2) throw InvalidArgumentException.entry(CliFlags.OTEL_HEADERS, pair)
            val (key, value) = parts.map { it.trim() }
            if (key.isEmpty() || value.isEmpty()) throw InvalidArgumentException.entry(CliFlags.OTEL_HEADERS, pair)
            key to value
        }
}

internal fun ParsedArgs.parseOtelConfig(): OtelConfig = OtelConfig(
    exporter = parseOtelExporter(),
    endpoint = value(CliFlags.OTEL_ENDPOINT),
    headers = parseOtelHeaders(),
    timeoutMs = intValue(CliFlags.OTEL_TIMEOUT_MS, OtelConfig.DEFAULT_OTEL_TIMEOUT_MS),
    serviceName = value(CliFlags.OTEL_SERVICE_NAME) ?: OtelConfig.DEFAULT_OTEL_SERVICE_NAME
)

internal fun ParsedArgs.resolveSecretDir(configDir: Path?, provider: SecretProviderType): String? {
    if (provider != SecretProviderType.FILE) return null
    return value(CliFlags.SECRET_DIR) ?: configDir?.resolve(CliDefaults.SECRETS_DIR)?.toString()
}
