package com.mustafadakhel.oag.inspection.injection

data class TokenEncoding(val ids: LongArray, val attentionMask: LongArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TokenEncoding) return false
        return ids.contentEquals(other.ids) && attentionMask.contentEquals(other.attentionMask)
    }

    override fun hashCode(): Int = 31 * ids.contentHashCode() + attentionMask.contentHashCode()
}

fun interface Tokenizer {
    fun encode(text: String, maxLength: Int): TokenEncoding
}
