package com.mustafadakhel.oag.app

import com.mustafadakhel.oag.policy.validation.PolicyValidationException

import java.io.IOException

internal data class CliError(
    val code: CliErrorCode,
    val message: String
)

internal fun classifyCliError(error: Throwable): CliError {
    val message = error.message ?: CliErrorCode.COMMAND_FAILED.code()
    val code = when (error) {
        is UnknownCommandException -> CliErrorCode.UNKNOWN_COMMAND
        is MissingArgumentException -> CliErrorCode.MISSING_ARGUMENT
        is InvalidArgumentException -> CliErrorCode.INVALID_ARGUMENT
        is ConfigException -> CliErrorCode.CONFIG_ERROR
        is PolicyValidationException -> CliErrorCode.POLICY_VALIDATION_FAILED
        is IOException -> CliErrorCode.IO_ERROR
        else -> CliErrorCode.COMMAND_FAILED
    }
    return CliError(code, message)
}
