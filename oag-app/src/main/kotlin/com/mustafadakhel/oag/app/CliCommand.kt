package com.mustafadakhel.oag.app

import java.io.PrintStream

internal fun interface CliCommand {
    fun execute(args: ParsedArgs, out: PrintStream): Int
}
