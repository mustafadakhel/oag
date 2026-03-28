/*
 * Copyright 2026 Mustafa Dakhel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.cachedRegex
import com.mustafadakhel.oag.inspection.content.AhoCorasickAutomaton
import com.mustafadakhel.oag.isRegexSafe

data class ClaimMatch(
    val category: String,
    val pattern: String
)

class ImpossibleClaimMatcher private constructor(
    private val automaton: AhoCorasickAutomaton?,
    private val containsIndex: List<Pair<String, String>>,
    private val regexPatterns: List<Triple<String, String, Regex>>
) {

    fun match(text: String): List<ClaimMatch> {
        val matches = mutableListOf<ClaimMatch>()

        if (automaton != null) {
            val matcher = automaton.newMatcher()
            val hits = matcher.feed(text.toByteArray(Charsets.UTF_8))
            for (hit in hits) {
                val (category, pattern) = containsIndex[hit.patternIndex]
                matches.add(ClaimMatch(category, pattern))
            }
        }

        for ((category, pattern, regex) in regexPatterns) {
            if (regex.containsMatchIn(text)) {
                matches.add(ClaimMatch(category, pattern))
            }
        }

        return matches
    }

    companion object {
        private const val RESOURCE_PATH = "/impossible-claims.yaml"

        fun loadDefault(): ImpossibleClaimMatcher = load(
            requireNotNull(ImpossibleClaimMatcher::class.java.getResourceAsStream(RESOURCE_PATH)) {
                "Built-in impossible-claims.yaml resource not found"
            }.bufferedReader().readText()
        )

        fun load(yamlText: String): ImpossibleClaimMatcher {
            val categories = parseClaimsYaml(yamlText)
            return build(categories)
        }

        private fun build(categories: Map<String, ClaimCategory>): ImpossibleClaimMatcher {
            val containsPatterns = mutableListOf<String>()
            val containsIndex = mutableListOf<Pair<String, String>>()
            val regexPatterns = mutableListOf<Triple<String, String, Regex>>()

            for ((category, claims) in categories) {
                for (pattern in claims.contains) {
                    containsPatterns.add(pattern)
                    containsIndex.add(category to pattern)
                }
                for (pattern in claims.regex) {
                    if (isRegexSafe(pattern)) {
                        regexPatterns.add(Triple(category, pattern, cachedRegex(pattern)))
                    }
                }
            }

            val automaton = if (containsPatterns.isNotEmpty()) {
                AhoCorasickAutomaton.build(containsPatterns)
            } else null

            return ImpossibleClaimMatcher(automaton, containsIndex, regexPatterns)
        }
    }
}

internal data class ClaimCategory(
    val contains: List<String> = emptyList(),
    val regex: List<String> = emptyList()
)

internal fun parseClaimsYaml(text: String): Map<String, ClaimCategory> {
    val categories = mutableMapOf<String, ClaimCategory>()
    var currentCategory: String? = null
    var currentSection: String? = null
    val containsList = mutableListOf<String>()
    val regexList = mutableListOf<String>()

    fun flushCategory() {
        currentCategory?.let {
            categories[it] = ClaimCategory(containsList.toList(), regexList.toList())
            containsList.clear()
            regexList.clear()
        }
    }

    for (line in text.lines()) {
        val trimmed = line.trimEnd()
        if (trimmed.isBlank() || trimmed.startsWith("#")) continue

        when {
            !trimmed.startsWith(" ") && !trimmed.startsWith("-") && trimmed.endsWith(":") -> {
                flushCategory()
                currentCategory = trimmed.removeSuffix(":").trim()
                currentSection = null
            }
            trimmed.trimStart().let { it == "contains:" || it == "regex:" } -> {
                currentSection = trimmed.trimStart().removeSuffix(":")
            }
            trimmed.trimStart().startsWith("- ") -> {
                val raw = trimmed.trimStart().removePrefix("- ").trim()
                val value = when {
                    raw.startsWith("\"") && raw.endsWith("\"") ->
                        raw.removeSurrounding("\"").replace("\\\\", "\u0000").replace("\\\"", "\"").replace("\u0000", "\\")
                    raw.startsWith("'") && raw.endsWith("'") ->
                        raw.removeSurrounding("'")
                    else -> raw
                }
                when (currentSection) {
                    "contains" -> containsList.add(value)
                    "regex" -> regexList.add(value)
                }
            }
        }
    }
    flushCategory()
    return categories
}
