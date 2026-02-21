package com.mustafadakhel.oag.policy.evaluation

import java.net.URLDecoder

internal data class ParsedQueryParams(
    val params: Map<String, List<String>>,
    // Security: tracks whether any key or value had invalid percent-encoding.
    // Consumers use this to fail-closed (return no-match), preventing attackers
    // from smuggling query parameters past policy rules via malformed encoding.
    val hasInvalidEncoding: Boolean
)

internal fun parseQueryParams(path: String): ParsedQueryParams {
    val queryStart = path.indexOf('?')
    if (queryStart == -1) return ParsedQueryParams(emptyMap(), false)
    val queryString = path.substring(queryStart + 1)
    if (queryString.isEmpty()) return ParsedQueryParams(emptyMap(), false)
    var invalidEncoding = false
    val pairs = queryString.split("&")
        .map { pair ->
            val eqIndex = pair.indexOf('=')
            if (eqIndex == -1) {
                val decoded = runCatching { URLDecoder.decode(pair, Charsets.UTF_8) }.getOrElse {
                    invalidEncoding = true
                    pair
                }
                decoded to ""
            } else {
                val rawKey = pair.substring(0, eqIndex)
                val rawValue = pair.substring(eqIndex + 1)
                val key = runCatching { URLDecoder.decode(rawKey, Charsets.UTF_8) }.getOrElse {
                    invalidEncoding = true
                    rawKey
                }
                val value = runCatching { URLDecoder.decode(rawValue, Charsets.UTF_8) }.getOrElse {
                    invalidEncoding = true
                    rawValue
                }
                key to value
            }
        }
        .groupBy({ it.first }, { it.second })
    return ParsedQueryParams(pairs, invalidEncoding)
}
