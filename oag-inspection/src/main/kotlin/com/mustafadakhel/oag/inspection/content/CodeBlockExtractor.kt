package com.mustafadakhel.oag.inspection.content

data class ExtractedCodeBlock(
    val code: String,
    val language: String?,
    val source: CodeBlockSource
)

enum class CodeBlockSource {
    MARKDOWN_FENCE,
    JSON_TOOL_CALL
}

private const val MAX_CODE_SCAN_BODY_SIZE = 524_288

private val MARKDOWN_FENCE_REGEX = Regex("""```(\w{0,30})\n([\s\S]*?)```""")
private val JSON_CODE_FIELD_REGEX = Regex(""""code"\s*:\s*"((?:[^"\\]|\\.)*)"""")

private val LANGUAGE_ALIASES = mapOf(
    "py" to "python",
    "js" to "javascript",
    "ts" to "typescript",
    "sh" to "bash",
    "shell" to "bash",
    "rb" to "ruby",
    "yml" to "yaml"
)

object CodeBlockExtractor {

    fun extract(text: String): List<ExtractedCodeBlock> {
        if (text.length > MAX_CODE_SCAN_BODY_SIZE) return emptyList()
        return extractMarkdownFences(text) + extractJsonCodeFields(text)
    }
}

private fun extractMarkdownFences(text: String): List<ExtractedCodeBlock> =
    MARKDOWN_FENCE_REGEX.findAll(text).map { match ->
        val rawLang = match.groupValues[1]
        val code = match.groupValues[2]
        ExtractedCodeBlock(
            code = code,
            language = normalizeLanguage(rawLang),
            source = CodeBlockSource.MARKDOWN_FENCE
        )
    }.toList()

private fun extractJsonCodeFields(text: String): List<ExtractedCodeBlock> =
    JSON_CODE_FIELD_REGEX.findAll(text).map { match ->
        val raw = match.groupValues[1]
        ExtractedCodeBlock(
            code = unescapeJsonString(raw),
            language = null,
            source = CodeBlockSource.JSON_TOOL_CALL
        )
    }.toList()

private fun normalizeLanguage(raw: String): String? {
    val trimmed = raw.trim().lowercase()
    if (trimmed.isBlank()) return null
    return LANGUAGE_ALIASES[trimmed] ?: trimmed
}

private fun unescapeJsonString(raw: String): String = raw
    .replace("\\\\", "\\")
    .replace("\\\"", "\"")
    .replace("\\n", "\n")
    .replace("\\t", "\t")
