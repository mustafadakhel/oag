package com.mustafadakhel.oag.enforcement

data class TokenUsage(
    val promptTokens: Long?,
    val completionTokens: Long?,
    val totalTokens: Long
)

object TokenUsageExtractor {

    private val TOTAL_TOKENS = Regex(""""total_tokens"\s*:\s*(\d+)""")
    private val PROMPT_TOKENS = Regex(""""(?:prompt_tokens|input_tokens)"\s*:\s*(\d+)""")
    private val COMPLETION_TOKENS = Regex(""""(?:completion_tokens|output_tokens)"\s*:\s*(\d+)""")

    fun extract(responseBody: String): TokenUsage? {
        val prompt = PROMPT_TOKENS.find(responseBody)?.groupValues?.get(1)?.toLongOrNull()
        val completion = COMPLETION_TOKENS.find(responseBody)?.groupValues?.get(1)?.toLongOrNull()
        val total = TOTAL_TOKENS.find(responseBody)?.groupValues?.get(1)?.toLongOrNull()
            ?: sumOrNull(prompt, completion)
            ?: return null
        return TokenUsage(promptTokens = prompt, completionTokens = completion, totalTokens = total)
    }

    private fun sumOrNull(a: Long?, b: Long?): Long? =
        if (a != null && b != null) a + b else null
}
