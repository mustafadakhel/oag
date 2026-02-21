package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.shannonEntropy

// Base64 uses 64 chars -> max Shannon entropy ~6.0 bits/char; 4.0 catches high-entropy sequences
// while ignoring structured text (English prose ~1.0-3.5 bits/char).
private const val BASE64_ENTROPY_THRESHOLD = 4.0
private const val MIN_ENTROPY_LENGTH = 40
private val BASE64_PATTERN = Regex("[A-Za-z0-9+/\\-_]{20,}={0,2}")

fun String.looksLikeBase64(minLength: Int = MIN_ENTROPY_LENGTH): Boolean {
    if (length < minLength) return false
    if (!BASE64_PATTERN.containsMatchIn(this)) return false
    return shannonEntropy() > BASE64_ENTROPY_THRESHOLD
}
