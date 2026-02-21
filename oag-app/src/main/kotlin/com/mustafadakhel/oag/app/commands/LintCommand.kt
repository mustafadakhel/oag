package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.app.configDirPath
import com.mustafadakhel.oag.app.policyService
import com.mustafadakhel.oag.policy.validation.lintPolicy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

internal val LintCommand = CliCommand { args, out ->
    val configDir = args.configDirPath()
    val policyService = args.policyService(configDir)
    val warnings = lintPolicy(policyService.current)

    if (args.hasFlag(CliFlags.JSON)) {
        out.println(cliJson.encodeToString(LintJsonOutput(
            ok = warnings.isEmpty(),
            warningCount = warnings.size,
            warnings = warnings.map { w ->
                LintWarningJson(
                    code = w.code.name,
                    message = w.message,
                    ruleId = w.ruleId,
                    ruleIndex = w.ruleIndex,
                    section = w.section
                )
            }
        )))
    } else {
        if (warnings.isEmpty()) {
            out.println("ok no warnings")
        } else {
            warnings.forEach { w -> out.println("warning [${w.code.name}] ${w.message}") }
            out.println("${warnings.size} warning(s) found")
        }
    }

    if (warnings.isEmpty()) 0 else 1
}

@Serializable
internal data class LintJsonOutput(
    val ok: Boolean,
    @SerialName("warning_count") val warningCount: Int,
    val warnings: List<LintWarningJson>
)

@Serializable
internal data class LintWarningJson(
    val code: String,
    val message: String,
    @SerialName("rule_id") val ruleId: String?,
    @SerialName("rule_index") val ruleIndex: Int?,
    val section: String?
)
