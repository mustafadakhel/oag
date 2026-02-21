package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.app.MissingArgumentException
import com.mustafadakhel.oag.label
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import com.mustafadakhel.oag.policy.distribution.RuleDiff
import com.mustafadakhel.oag.policy.distribution.diffPolicies
import com.mustafadakhel.oag.policy.distribution.loadAndValidatePolicySource
import com.mustafadakhel.oag.policy.evaluation.normalize

import java.nio.file.Path

internal val DiffCommand = CliCommand { args, out ->
    val jsonMode = args.hasFlag(CliFlags.JSON)
    if (args.positional.size < 2) throw MissingArgumentException.forArgument("<policy1> <policy2>")

    val (oldPath, newPath) = args.positional
    val oldPolicy = loadAndValidatePolicySource(Path.of(oldPath), publicKey = null, requireSignature = false).policy.normalize()
    val newPolicy = loadAndValidatePolicySource(Path.of(newPath), publicKey = null, requireSignature = false).policy.normalize()
    val result = diffPolicies(oldPolicy, newPolicy)

    if (jsonMode) {
        val output = DiffJsonOutput(
            hasChanges = result.hasChanges,
            defaultsChanged = result.defaultsChanged,
            defaultsDetails = result.defaultsDetails,
            ruleDiffs = result.ruleDiffs.map { it.toJson() },
            secretScopeDiffs = result.secretScopeDiffs.map { it.toJson() }
        )
        out.println(cliJson.encodeToString(output))
    } else {
        if (!result.hasChanges) {
            out.println("no changes")
            return@CliCommand 0
        }
        if (result.defaultsChanged) {
            out.println("defaults changed:")
            result.defaultsDetails.forEach { out.println("  $it") }
        }
        fun printDiffs(diffs: List<RuleDiff>) {
            diffs.forEach { diff ->
                val id = diff.id ?: "(no id)"
                out.println("${diff.section} ${diff.change.label()}: $id")
                diff.details.forEach { out.println("  $it") }
            }
        }
        printDiffs(result.ruleDiffs)
        printDiffs(result.secretScopeDiffs)
    }
    0
}

private fun RuleDiff.toJson() = RuleDiffJson(
    section = section,
    id = id,
    change = change.label(),
    details = details
)

@Serializable
internal data class DiffJsonOutput(
    val ok: Boolean = true,
    @SerialName("has_changes") val hasChanges: Boolean,
    @SerialName("defaults_changed") val defaultsChanged: Boolean,
    @SerialName("defaults_details") val defaultsDetails: List<String>,
    @SerialName("rule_diffs") val ruleDiffs: List<RuleDiffJson>,
    @SerialName("secret_scope_diffs") val secretScopeDiffs: List<RuleDiffJson>
)

@Serializable
internal data class RuleDiffJson(
    val section: String,
    val id: String?,
    val change: String,
    val details: List<String>
)
