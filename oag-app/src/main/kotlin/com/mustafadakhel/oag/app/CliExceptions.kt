package com.mustafadakhel.oag.app

internal open class CliException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

internal class UnknownCommandException(command: String, available: List<String>) :
    CliException("Unknown command '$command'. Available: ${available.joinToString(", ")}")

internal class MissingArgumentException private constructor(message: String) : CliException(message) {
    companion object {
        fun forFlag(flag: String) = MissingArgumentException("Missing value for $flag")
        fun forArgument(name: String) = MissingArgumentException("Missing required argument $name")
    }
}

internal class InvalidArgumentException private constructor(message: String) : CliException(message) {
    companion object {
        fun integer(name: String, raw: String) = InvalidArgumentException("Invalid integer for $name: $raw")
        fun number(name: String, raw: String) = InvalidArgumentException("Invalid number for $name: $raw")
        fun value(flag: String, raw: String) = InvalidArgumentException("Invalid $flag value: $raw")
        fun entry(flag: String, entry: String) = InvalidArgumentException("Invalid $flag entry: $entry")
        fun of(message: String) = InvalidArgumentException(message)
    }
}

internal class ConfigException(message: String) : CliException(message)
