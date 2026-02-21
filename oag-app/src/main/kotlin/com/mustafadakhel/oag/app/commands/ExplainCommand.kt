package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.app.configDirPath
import com.mustafadakhel.oag.app.parseRequestSpec
import com.mustafadakhel.oag.app.policyService

import java.util.Locale

internal val ExplainCommand = CliCommand { args, out ->
    val jsonMode = args.hasFlag(CliFlags.JSON)
    val verboseMode = args.hasFlag(CliFlags.VERBOSE)
    val configDir = args.configDirPath()
    val requestSpec = args.requireValue(CliFlags.REQUEST)
    val request = parseRequestSpec(requestSpec, "Invalid ${CliFlags.REQUEST} format. Use: \"METHOD https://host/path\"")
        .let { it.copy(method = it.method.uppercase(Locale.ROOT)) }
    val decision = args.policyService(configDir, allowPositional = false).evaluate(request)
    val record = decision.toDecisionRecord()
    if (jsonMode) {
        val requestInfo = RequestSummary(
            scheme = request.scheme,
            host = request.host,
            port = request.port,
            method = request.method,
            path = request.path
        )
        out.println(formatExplainJson(record, verboseMode, requestInfo))
    } else {
        out.println(formatExplainText(record))
    }
    0
}
