package com.mustafadakhel.oag.app

import com.mustafadakhel.oag.label

internal enum class CliCommandName {
    RUN,
    DOCTOR,
    EXPLAIN,
    TEST,
    HASH,
    BUNDLE,
    VERIFY,
    LINT,
    SIMULATE,
    DIFF,
    HELP;

    fun cliName(): String = label()
}
