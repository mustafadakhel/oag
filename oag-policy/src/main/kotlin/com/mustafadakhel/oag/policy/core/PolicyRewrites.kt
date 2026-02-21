package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.label

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

import java.util.Locale

enum class HeaderRewriteAction {
    SET,
    REMOVE,
    APPEND
}

@Serializable
data class PolicyHeaderRewrite(
    val action: HeaderRewriteAction,
    val header: String,
    val value: String? = null
)

enum class ResponseRewriteAction {
    REDACT,
    REMOVE_HEADER,
    SET_HEADER
}

@Serializable(with = PolicyResponseRewriteSerializer::class)
sealed class PolicyResponseRewrite {
    abstract val action: ResponseRewriteAction

    data class Redact(
        val pattern: String,
        val replacement: String? = null
    ) : PolicyResponseRewrite() {
        override val action: ResponseRewriteAction get() = ResponseRewriteAction.REDACT
    }

    data class RemoveHeader(
        val header: String
    ) : PolicyResponseRewrite() {
        override val action: ResponseRewriteAction get() = ResponseRewriteAction.REMOVE_HEADER
    }

    data class SetHeader(
        val header: String,
        val value: String
    ) : PolicyResponseRewrite() {
        override val action: ResponseRewriteAction get() = ResponseRewriteAction.SET_HEADER
    }
}

@Serializable
private data class ResponseRewriteSurrogate(
    val action: String,
    val pattern: String? = null,
    val replacement: String? = null,
    val header: String? = null,
    val value: String? = null
)

internal object PolicyResponseRewriteSerializer : KSerializer<PolicyResponseRewrite> {
    override val descriptor: SerialDescriptor = ResponseRewriteSurrogate.serializer().descriptor

    override fun deserialize(decoder: Decoder): PolicyResponseRewrite {
        val surrogate = decoder.decodeSerializableValue(ResponseRewriteSurrogate.serializer())
        val action = requireNotNull(
            ResponseRewriteAction.entries.firstOrNull { it.label() == surrogate.action.trim().lowercase(Locale.ROOT) }
        ) { "Unknown response rewrite action: ${surrogate.action}" }
        return when (action) {
            ResponseRewriteAction.REDACT -> PolicyResponseRewrite.Redact(
                pattern = requireNotNull(surrogate.pattern) { "REDACT rewrite requires 'pattern'" },
                replacement = surrogate.replacement
            )
            ResponseRewriteAction.REMOVE_HEADER -> PolicyResponseRewrite.RemoveHeader(
                header = requireNotNull(surrogate.header) { "REMOVE_HEADER rewrite requires 'header'" }
            )
            ResponseRewriteAction.SET_HEADER -> PolicyResponseRewrite.SetHeader(
                header = requireNotNull(surrogate.header) { "SET_HEADER rewrite requires 'header'" },
                value = requireNotNull(surrogate.value) { "SET_HEADER rewrite requires 'value'" }
            )
        }
    }

    override fun serialize(encoder: Encoder, value: PolicyResponseRewrite) {
        val surrogate = when (value) {
            is PolicyResponseRewrite.Redact -> ResponseRewriteSurrogate(
                action = value.action.label(),
                pattern = value.pattern,
                replacement = value.replacement
            )
            is PolicyResponseRewrite.RemoveHeader -> ResponseRewriteSurrogate(
                action = value.action.label(),
                header = value.header
            )
            is PolicyResponseRewrite.SetHeader -> ResponseRewriteSurrogate(
                action = value.action.label(),
                header = value.header,
                value = value.value
            )
        }
        encoder.encodeSerializableValue(ResponseRewriteSurrogate.serializer(), surrogate)
    }
}

@Serializable
data class PolicyErrorResponse(
    val status: Int? = null,
    val body: String? = null,
    @SerialName("content_type") val contentType: String? = null
)
