package com.mustafadakhel.oag.inspection.injection

import java.nio.file.Path

class DjlHuggingFaceTokenizer private constructor(
    private val delegate: ai.djl.huggingface.tokenizers.HuggingFaceTokenizer
) : Tokenizer, AutoCloseable {

    override fun encode(text: String, maxLength: Int): TokenEncoding {
        val encoding = delegate.encode(text.take(maxLength * 4))
        val ids = encoding.ids
        val mask = encoding.attentionMask
        val truncatedIds = if (ids.size > maxLength + 2) ids.copyOf(maxLength + 2) else ids
        val truncatedMask = if (mask.size > maxLength + 2) mask.copyOf(maxLength + 2) else mask
        return TokenEncoding(truncatedIds, truncatedMask)
    }

    override fun close() {
        delegate.close()
    }

    companion object {
        fun createOrNull(
            tokenizerPath: String,
            onError: (String) -> Unit = {}
        ): DjlHuggingFaceTokenizer? = runCatching {
            val hfTokenizer = ai.djl.huggingface.tokenizers.HuggingFaceTokenizer.newInstance(
                Path.of(tokenizerPath)
            )
            DjlHuggingFaceTokenizer(hfTokenizer)
        }.onFailure { e ->
            onError("DJL HuggingFace tokenizer creation failed: ${e.message}")
        }.getOrNull()

        fun isAvailable(): Boolean = runCatching {
            Class.forName("ai.djl.huggingface.tokenizers.HuggingFaceTokenizer")
        }.isSuccess
    }
}
