package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.FORBIDDEN_REWRITE_HEADERS
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.HeaderRewriteAction
import com.mustafadakhel.oag.policy.core.PolicyHeaderRewrite
import com.mustafadakhel.oag.policy.core.PolicyResponseRewrite

import java.util.Locale

internal fun PolicyHeaderRewrite.validate(base: String): List<ValidationError> = buildList {
    when {
        header.isBlank() ->
            add(ValidationError("$base.header", ValidationMessage.MUST_NOT_BE_BLANK))
        header.any(Char::isWhitespace) ->
            add(ValidationError("$base.header", ValidationMessage.MUST_NOT_CONTAIN_WHITESPACE))
        header.trim().lowercase(Locale.ROOT) in FORBIDDEN_REWRITE_HEADERS ->
            add(ValidationError("$base.header", "Cannot rewrite reserved header '${header.trim()}'"))
    }
    if (action != HeaderRewriteAction.REMOVE && value.isNullOrEmpty()) {
        add(ValidationError("$base.value", "Must not be empty for ${action.label()} action"))
    }
}

internal fun PolicyResponseRewrite.validate(base: String): List<ValidationError> = buildList {
    when (val rw = this@validate) {
        is PolicyResponseRewrite.Redact -> {
            if (rw.pattern.isEmpty()) {
                add(ValidationError("$base.pattern", "Must not be empty for redact action"))
            } else {
                runCatching { Regex(rw.pattern) }.onFailure {
                    add(ValidationError("$base.pattern", "Invalid regex: ${it.message}"))
                }
            }
        }
        is PolicyResponseRewrite.RemoveHeader -> {
            if (rw.header.isBlank()) {
                add(ValidationError("$base.header", "Must not be blank for remove_header action"))
            } else if (rw.header.trim().lowercase(Locale.ROOT) in FORBIDDEN_REWRITE_HEADERS) {
                add(ValidationError("$base.header", "Cannot rewrite reserved response header '${rw.header.trim()}'"))
            }
        }
        is PolicyResponseRewrite.SetHeader -> {
            if (rw.header.isBlank()) {
                add(ValidationError("$base.header", "Must not be blank for set_header action"))
            } else if (rw.header.trim().lowercase(Locale.ROOT) in FORBIDDEN_REWRITE_HEADERS) {
                add(ValidationError("$base.header", "Cannot rewrite reserved response header '${rw.header.trim()}'"))
            }
            if (rw.value.isEmpty()) {
                add(ValidationError("$base.value", "Must not be empty for set_header action"))
            }
        }
    }
}
