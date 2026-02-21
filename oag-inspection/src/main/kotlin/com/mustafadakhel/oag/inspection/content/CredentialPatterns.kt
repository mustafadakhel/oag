package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.inspection.PatternEntry
import com.mustafadakhel.oag.inspection.matchingNames

object CredentialPatterns {

    val AWS_ACCESS_KEY: List<PatternEntry> = listOf(
        PatternEntry("aws_access_key", Regex("""(?:AKIA|ASIA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}"""))
    )

    val GITHUB_TOKEN: List<PatternEntry> = listOf(
        PatternEntry("github_pat", Regex("""ghp_[A-Za-z0-9_]{36,255}""")),
        PatternEntry("github_oauth", Regex("""gho_[A-Za-z0-9_]{36,255}""")),
        PatternEntry("github_user_to_server", Regex("""ghu_[A-Za-z0-9_]{36,255}""")),
        PatternEntry("github_server_to_server", Regex("""ghs_[A-Za-z0-9_]{36,255}"""))
    )

    val PRIVATE_KEY: List<PatternEntry> = listOf(
        PatternEntry("private_key", Regex("""-----BEGIN[A-Z ]*PRIVATE KEY-----"""))
    )

    val JWT: List<PatternEntry> = listOf(
        PatternEntry("jwt", Regex("""eyJ[A-Za-z0-9_-]{10,1024}\.[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,1024}"""))
    )

    val GENERIC_API_KEY: List<PatternEntry> = listOf(
        PatternEntry("generic_api_key", Regex("""(?:api_key|apikey|secret_key|secretkey|access_token)[\s]*[:=][\s]*\S{16,256}""", RegexOption.IGNORE_CASE))
    )

    val SLACK_TOKEN: List<PatternEntry> = listOf(
        PatternEntry("slack_token", Regex("""xox[bpoas]-[A-Za-z0-9-]{10,255}"""))
    )

    val BEARER_TOKEN: List<PatternEntry> = listOf(
        PatternEntry("bearer_token", Regex("""[Bb]earer\s+[A-Za-z0-9_\-.~+/]{20,2048}"""))
    )

    val ALL: List<PatternEntry> = AWS_ACCESS_KEY + GITHUB_TOKEN + PRIVATE_KEY +
        JWT + GENERIC_API_KEY + SLACK_TOKEN + BEARER_TOKEN

    fun matches(content: String): List<String> = ALL.matchingNames(content)
}
