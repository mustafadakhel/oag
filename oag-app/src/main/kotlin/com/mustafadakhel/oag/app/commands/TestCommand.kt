package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.app.configDirPath
import com.mustafadakhel.oag.app.policyService
import com.mustafadakhel.oag.app.runPolicyCases
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

import java.nio.file.Path

internal val TestCommand = CliCommand { args, out ->
    val jsonMode = args.hasFlag(CliFlags.JSON)
    val verboseMode = args.hasFlag(CliFlags.VERBOSE)
    val configDir = args.configDirPath()

    val result = runPolicyCases(
        policyService = args.policyService(configDir),
        casesPath = Path.of(args.requireValue(CliFlags.CASES))
    )

    if (jsonMode) {
        out.println(cliJson.encodeToString(TestJsonOutput(
            ok = result.failed == 0,
            total = result.total,
            passed = result.passed,
            failed = result.failed,
            failures = result.failures,
            cases = if (verboseMode) result.caseResults.map { case ->
                TestCaseJson(
                    name = case.name,
                    ok = case.ok,
                    expectedAction = case.expectedAction,
                    expectedReason = case.expectedReason,
                    actualAction = case.actualAction,
                    actualReason = case.actualReason
                )
            } else null
        )))
        return@CliCommand if (result.failed == 0) 0 else 1
    }

    if (result.failed == 0) {
        out.println("ok total=${result.total} passed=${result.passed} failed=0")
        return@CliCommand 0
    }

    result.failures.forEach { out.println("fail $it") }
    out.println("policy tests failed: ${result.failed}/${result.total}")
    return@CliCommand 1
}

@Serializable
internal data class TestJsonOutput(
    val ok: Boolean,
    val total: Int,
    val passed: Int,
    val failed: Int,
    val failures: List<String>,
    val cases: List<TestCaseJson>? = null
)

@Serializable
internal data class TestCaseJson(
    val name: String,
    val ok: Boolean,
    @SerialName("expected_action") val expectedAction: String,
    @SerialName("expected_reason") val expectedReason: String?,
    @SerialName("actual_action") val actualAction: String,
    @SerialName("actual_reason") val actualReason: String
)
