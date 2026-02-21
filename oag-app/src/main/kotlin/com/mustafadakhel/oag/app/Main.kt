package com.mustafadakhel.oag.app

import com.mustafadakhel.oag.app.commands.BundleCommand
import com.mustafadakhel.oag.app.commands.DiffCommand
import com.mustafadakhel.oag.app.commands.DoctorCommand
import com.mustafadakhel.oag.app.commands.ExplainCommand
import com.mustafadakhel.oag.app.commands.HashCommand
import com.mustafadakhel.oag.app.commands.HelpCommand
import com.mustafadakhel.oag.app.commands.LintCommand
import com.mustafadakhel.oag.app.commands.MainErrorJson
import com.mustafadakhel.oag.app.commands.RunCommand
import com.mustafadakhel.oag.app.commands.SimulateCommand
import com.mustafadakhel.oag.app.commands.TestCommand
import com.mustafadakhel.oag.app.commands.cliJson

import kotlin.system.exitProcess

import java.io.PrintStream

private val COMMANDS: Map<String, CliCommand> = buildMap {
    CliCommandName.entries.forEach { put(it.cliName(), it.handler()) }
    put(CliFlags.HELP_LONG, HelpCommand)
    put(CliFlags.HELP_SHORT, HelpCommand)
}

private val NON_JSON_COMMANDS = setOf(
    CliCommandName.RUN.cliName(),
    CliCommandName.HELP.cliName(),
    CliFlags.HELP_LONG,
    CliFlags.HELP_SHORT
)

internal val COMMAND_NAMES: List<String> = CliCommandName.entries.map { it.cliName() }
internal val JSON_MODE_COMMANDS: List<String> = COMMAND_NAMES.filter { it != CliCommandName.RUN.cliName() }

fun main(args: Array<String>): Unit = exitProcess(runCli(args, System.out, System.err))

fun runCli(
    args: Array<String>,
    out: PrintStream,
    err: PrintStream
): Int {
    val command = args.firstOrNull()
    val commandArgs = resolveCommandArgs(command, args)
    val jsonMode = command != null && command !in NON_JSON_COMMANDS && CliFlags.JSON in commandArgs
    return runCatching { dispatch(command, args, commandArgs, out) }.fold(
        onSuccess = { it },
        onFailure = { reportError(it, jsonMode, out, err) }
    )
}

private fun resolveCommandArgs(
    command: String?,
    args: Array<String>
): Array<String> = if (command == CliCommandName.VERIFY.cliName()) {
    arrayOf(CliFlags.VERIFY) + args.drop(1)
} else {
    args.drop(1).toTypedArray()
}

private fun dispatch(
    command: String?,
    args: Array<String>,
    commandArgs: Array<String>,
    out: PrintStream
): Int {
    val handler = COMMANDS[command]
    return when {
        handler != null -> handler.execute(ParsedArgs(commandArgs), out)
        command == null || command.startsWith(CliFlags.FLAG_PREFIX) ->
            RunCommand.execute(ParsedArgs(args), out)
        else -> throw UnknownCommandException(command, COMMAND_NAMES)
    }
}

private fun reportError(
    throwable: Throwable,
    jsonMode: Boolean,
    out: PrintStream,
    err: PrintStream
): Int {
    val error = classifyCliError(throwable)
    if (jsonMode) {
        out.println(cliJson.encodeToString(
            MainErrorJson(
                errorCode = error.code.code(),
                error = error.message
            )
        ))
    } else {
        err.println("${error.code.code()}: ${error.message}")
    }
    return 1
}

private fun CliCommandName.handler(): CliCommand = when (this) {
    CliCommandName.RUN -> RunCommand
    CliCommandName.DOCTOR -> DoctorCommand
    CliCommandName.EXPLAIN -> ExplainCommand
    CliCommandName.TEST -> TestCommand
    CliCommandName.HASH -> HashCommand
    CliCommandName.BUNDLE -> BundleCommand
    CliCommandName.VERIFY -> HashCommand
    CliCommandName.LINT -> LintCommand
    CliCommandName.SIMULATE -> SimulateCommand
    CliCommandName.DIFF -> DiffCommand
    CliCommandName.HELP -> HelpCommand
}
