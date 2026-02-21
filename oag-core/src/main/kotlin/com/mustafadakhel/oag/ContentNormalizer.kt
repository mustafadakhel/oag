package com.mustafadakhel.oag

import java.text.Normalizer

private val ZERO_WIDTH_CHARS = Regex("[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E\u200E\u200F\u061C\u2028\u2029]")

fun String.normalizeContent(): String =
    Normalizer.normalize(ZERO_WIDTH_CHARS.replace(this, ""), Normalizer.Form.NFKC)
