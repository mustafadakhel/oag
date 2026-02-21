package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.shannonEntropy

object PathAnalyzer {
    private val TRAVERSAL_PATTERNS = listOf(
        Regex("""\.\./"""),
        Regex("""\.\.$"""),
        Regex("""\.\.\\"""),
        Regex("""\.\.%2f""", RegexOption.IGNORE_CASE),
        Regex("""\.\.%5c""", RegexOption.IGNORE_CASE),
        Regex("""%2e%2e(?:/|%5c)""", RegexOption.IGNORE_CASE),
        Regex("""%2e\.(?:/|%5c)""", RegexOption.IGNORE_CASE),
        Regex("""\.%2e(?:/|%5c)""", RegexOption.IGNORE_CASE),
        Regex("""%2e%2e$""", RegexOption.IGNORE_CASE)
    )

    private val DOUBLE_ENCODING_PATTERN = Regex("""%25[0-9A-Fa-f]{2}""")

    fun detectPathTraversal(path: String): Boolean =
        TRAVERSAL_PATTERNS.any { it.containsMatchIn(path) }
    fun detectDoubleEncoding(path: String): Boolean =
        DOUBLE_ENCODING_PATTERN.containsMatchIn(path)
}

fun String.maxSegmentEntropy(): Double {
    val pathOnly = substringBefore('?').substringBefore('#')
    val segments = pathOnly.split('/').filter { it.isNotEmpty() }
    if (segments.isEmpty()) return 0.0
    return segments.maxOf { it.shannonEntropy() }
}
