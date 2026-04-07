package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.FindingSeverity
import com.mustafadakhel.oag.inspection.RecommendedAction

data class CodeSecurityRule(
    val id: String,
    val cwe: String,
    val regex: Regex,
    val severity: FindingSeverity,
    val description: String,
    val recommendedAction: RecommendedAction = RecommendedAction.LOG
)

object CodeSecurityRules {

    val SQL_INJECTION: List<CodeSecurityRule> = listOf(
        CodeSecurityRule(
            id = "sql_fstring",
            cwe = "CWE-89",
            regex = Regex("""f"(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]{0,500}\{""", RegexOption.IGNORE_CASE),
            severity = FindingSeverity.HIGH,
            description = "Python f-string used in SQL query"
        ),
        CodeSecurityRule(
            id = "sql_concat_execute",
            cwe = "CWE-89",
            regex = Regex("""\.execute\(\s*"[^"]{0,500}"\s*\+"""),
            severity = FindingSeverity.HIGH,
            description = "String concatenation in SQL execute call"
        )
    )

    val COMMAND_INJECTION: List<CodeSecurityRule> = listOf(
        CodeSecurityRule(
            id = "cmd_shell_true",
            cwe = "CWE-78",
            regex = Regex("""subprocess\.\w{0,30}\([^)]{0,500}shell\s*=\s*True[^)]{0,500}\)"""),
            severity = FindingSeverity.HIGH,
            description = "subprocess call with shell=True"
        ),
        CodeSecurityRule(
            id = "cmd_os_system",
            cwe = "CWE-78",
            regex = Regex("""os\.system\("""),
            severity = FindingSeverity.HIGH,
            description = "os.system() call"
        ),
        CodeSecurityRule(
            id = "cmd_eval_exec",
            cwe = "CWE-78",
            regex = Regex("""\b(?:eval|exec)\("""),
            severity = FindingSeverity.HIGH,
            description = "eval() or exec() call"
        )
    )

    val INSECURE_DESERIALIZATION: List<CodeSecurityRule> = listOf(
        CodeSecurityRule(
            id = "deser_pickle",
            cwe = "CWE-502",
            regex = Regex("""pickle\.loads?\("""),
            severity = FindingSeverity.HIGH,
            description = "Insecure pickle deserialization"
        ),
        CodeSecurityRule(
            id = "deser_yaml_unsafe",
            cwe = "CWE-502",
            regex = Regex("""yaml\.load\("""),
            severity = FindingSeverity.HIGH,
            description = "yaml.load() without SafeLoader"
        )
    )

    val WEAK_CRYPTO: List<CodeSecurityRule> = listOf(
        CodeSecurityRule(
            id = "crypto_md5",
            cwe = "CWE-327",
            regex = Regex("""(?:hashlib\.md5\(|MD5\.new\(|new MD5\(|createHash\([^)]{0,50}md5[^)]{0,50}\))"""),
            severity = FindingSeverity.MEDIUM,
            description = "Weak MD5 hash usage"
        )
    )

    val HARDCODED_SECRETS: List<CodeSecurityRule> = listOf(
        CodeSecurityRule(
            id = "secret_assignment",
            cwe = "CWE-798",
            regex = Regex(
                """(?:password|secret|api_key|apikey|token)\s*=\s*["'][^"']{8,128}["']""",
                RegexOption.IGNORE_CASE
            ),
            severity = FindingSeverity.HIGH,
            description = "Hardcoded secret in variable assignment"
        )
    )

    val ALL: List<CodeSecurityRule> = SQL_INJECTION + COMMAND_INJECTION +
        INSECURE_DESERIALIZATION + WEAK_CRYPTO + HARDCODED_SECRETS
}
