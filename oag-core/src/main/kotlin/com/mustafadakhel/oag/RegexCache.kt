package com.mustafadakhel.oag

internal const val MAX_REGEX_CACHE_SIZE = 256
internal const val MAX_REGEX_LENGTH = 1024

private val regexCache = ConcurrentLruMap<String, Regex>(MAX_REGEX_CACHE_SIZE)

fun clearRegexCache() {
    regexCache.clear()
}

fun isRegexSafe(pattern: String): Boolean {
    if (pattern.length > MAX_REGEX_LENGTH) return false
    if (hasNestedQuantifier(pattern)) return false
    return true
}

private val QUANTIFIER_CHARS = charArrayOf('+', '*', '?')

private fun hasNestedQuantifier(pattern: String): Boolean {
    var depth = 0
    val quantifiedDepths = mutableSetOf<Int>()
    var i = 0
    while (i < pattern.length) {
        val ch = pattern[i]
        if (ch == '\\') { i += 2; continue }
        when (ch) {
            '(' -> { depth++; i++ }
            ')' -> {
                val nextIdx = i + 1
                val hasQuantifier = nextIdx < pattern.length &&
                    (pattern[nextIdx] in QUANTIFIER_CHARS || pattern[nextIdx] == '{')
                if (hasQuantifier) {
                    if (depth in quantifiedDepths) return true
                    quantifiedDepths += depth
                }
                depth--
                i++
            }
            '+', '*' -> {
                if (depth > 0 && depth in quantifiedDepths) return true
                i++
            }
            else -> i++
        }
    }
    return false
}

fun cachedRegex(pattern: String): Regex =
    regexCache.getOrPut(pattern) {
        require(isRegexSafe(pattern)) { "regex pattern rejected: potential ReDoS or exceeds max length" }
        Regex(pattern)
    }

fun cachedRegex(pattern: String, options: Set<RegexOption>): Regex {
    if (options.isEmpty()) return cachedRegex(pattern)
    val key = "$pattern\u0000${options.sortedBy { it.ordinal }.joinToString(",")}"
    return regexCache.getOrPut(key) {
        require(isRegexSafe(pattern)) { "regex pattern rejected: potential ReDoS or exceeds max length" }
        Regex(pattern, options)
    }
}
