package com.mustafadakhel.oag.inspection.injection

class CharCodeTokenizer : Tokenizer {

    override fun encode(text: String, maxLength: Int): TokenEncoding {
        val tokens = mutableListOf(CLS_TOKEN_ID)
        for (char in text.take(maxLength)) {
            tokens.add(char.code.toLong())
        }
        tokens.add(SEP_TOKEN_ID)
        val ids = tokens.toLongArray()
        val attentionMask = LongArray(ids.size) { 1L }
        return TokenEncoding(ids, attentionMask)
    }

    companion object {
        private const val CLS_TOKEN_ID = 101L
        private const val SEP_TOKEN_ID = 102L
    }
}
