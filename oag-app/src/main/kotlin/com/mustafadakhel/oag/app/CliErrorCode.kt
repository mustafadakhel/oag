package com.mustafadakhel.oag.app

import com.mustafadakhel.oag.label

internal enum class CliErrorCode {
    UNKNOWN_COMMAND,
    MISSING_ARGUMENT,
    INVALID_ARGUMENT,
    CONFIG_ERROR,
    POLICY_VALIDATION_FAILED,
    IO_ERROR,
    COMMAND_FAILED;

    fun code(): String = label()
}
