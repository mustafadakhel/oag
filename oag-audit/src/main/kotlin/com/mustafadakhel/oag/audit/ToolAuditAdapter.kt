package com.mustafadakhel.oag.audit

import com.mustafadakhel.oag.REDACTED_SENTINEL

import java.util.Locale

class ToolAuditAdapter(
    private val auditLogger: AuditLogger,
    private val allowlist: Set<String> = emptySet()
) {
    private val normalizedAllowlist: Set<String> = allowlist.map { it.normalizeKey().lowercase(Locale.ROOT) }.toSet()

    fun logToolCall(input: ToolCallInput) {
        val grouped = input.parameters.keys.groupBy { it.normalizeKey() }
        val sortedKeys = grouped.keys.sorted()
        val redactedParameters = sortedKeys.associateWith { key ->
            val originals = grouped[key] ?: return@associateWith REDACTED
            val value = originals.firstNotNullOfOrNull { input.parameters[it] }
            redactValue(key, value)
        }

        auditLogger.logToolEvent(
            AuditToolEvent(
                oagVersion = input.oagVersion,
                policyHash = input.policyHash,
                agentId = input.agentId,
                sessionId = input.sessionId,
                tool = AuditTool(
                    name = input.name,
                    parameterKeys = sortedKeys,
                    parameters = redactedParameters,
                    responseBytes = input.responseBytes,
                    durationMs = input.durationMs,
                    errorCode = input.errorCode
                )
            )
        )
    }

    /** Sensitive-key patterns always win: even allowlisted keys are redacted if they match a sensitive pattern. */
    private fun redactValue(key: String, value: Any?): String {
        val normalizedKey = key.lowercase(Locale.ROOT)
        if (isSensitiveKey(normalizedKey)) return REDACTED
        if (!normalizedAllowlist.contains(normalizedKey)) return REDACTED
        return value.toSafeString()
    }

    private fun isSensitiveKey(key: String): Boolean =
        SENSITIVE_KEY_PATTERNS.any { it.containsMatchIn(key) }
}

private val REDACTED = REDACTED_SENTINEL
private const val MAX_VALUE_LENGTH = 256
private const val MAX_KEY_LENGTH = 128
private val PRINTABLE_ASCII_RANGE = 0x20..0x7E

private val SENSITIVE_KEY_PATTERNS = listOf(
    Regex("secret", RegexOption.IGNORE_CASE),
    Regex("token", RegexOption.IGNORE_CASE),
    Regex("password", RegexOption.IGNORE_CASE),
    Regex("api[_-]?key", RegexOption.IGNORE_CASE),
    Regex("auth", RegexOption.IGNORE_CASE),
    Regex("credential", RegexOption.IGNORE_CASE)
)

private fun String.sanitizeAscii(maxLength: Int): String {
    val safe = map { ch -> if (ch.code in PRINTABLE_ASCII_RANGE) ch else '?' }.joinToString("")
    return if (safe.length <= maxLength) safe else safe.take(maxLength)
}

private fun Any?.toSafeString(): String =
    if (this == null) "null" else toString().sanitizeAscii(MAX_VALUE_LENGTH)

private fun String.normalizeKey(): String =
    trim().sanitizeAscii(MAX_KEY_LENGTH)
