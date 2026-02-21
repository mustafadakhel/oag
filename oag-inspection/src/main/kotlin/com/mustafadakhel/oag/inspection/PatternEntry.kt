package com.mustafadakhel.oag.inspection

data class PatternEntry(val name: String, val regex: Regex)

fun List<PatternEntry>.matchingNames(content: String): List<String> =
    filter { it.regex.containsMatchIn(content) }.map { it.name }
