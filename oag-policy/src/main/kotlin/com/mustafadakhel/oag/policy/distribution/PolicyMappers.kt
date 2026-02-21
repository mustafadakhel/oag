package com.mustafadakhel.oag.policy.distribution

import com.charleskorn.kaml.Yaml
import com.charleskorn.kaml.YamlConfiguration

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

import kotlin.io.path.extension

import java.nio.file.Files
import java.nio.file.Path
import java.util.Locale

@PublishedApi internal val policyJson = Json {
    ignoreUnknownKeys = false
    isLenient = true
    encodeDefaults = true
}

@PublishedApi internal val policyYaml = Yaml(
    configuration = YamlConfiguration(
        encodeDefaults = true,
        decodeEnumCaseInsensitive = true
    )
)

fun isYamlPath(path: Path): Boolean =
    path.extension.lowercase(Locale.ROOT) in setOf("yaml", "yml")

inline fun <reified T> decodeFromPath(path: Path): T {
    val text = Files.readString(path)
    return if (isYamlPath(path)) {
        policyYaml.decodeFromString(text)
    } else {
        policyJson.decodeFromString(text)
    }
}

fun <T> decodeFromString(path: Path, deserializer: DeserializationStrategy<T>, text: String): T =
    if (isYamlPath(path)) {
        policyYaml.decodeFromString(deserializer, text)
    } else {
        policyJson.decodeFromString(deserializer, text)
    }

fun <T> encodeToString(path: Path, serializer: SerializationStrategy<T>, value: T): String =
    if (isYamlPath(path)) {
        policyYaml.encodeToString(serializer, value)
    } else {
        policyJson.encodeToString(serializer, value)
    }

fun <T> encodeToPath(path: Path, serializer: SerializationStrategy<T>, value: T) {
    Files.writeString(path, encodeToString(path, serializer, value))
}
