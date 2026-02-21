package com.mustafadakhel.oag.enforcement

sealed interface EnforcementAction {
    data object Allow : EnforcementAction
    data class Deny(val reason: String, val statusCode: Int = 403) : EnforcementAction
    data class Notify(val message: String, val data: Map<String, Any?> = emptyMap()) : EnforcementAction
    data class Redact(val target: String) : EnforcementAction
    data class Truncate(val maxLength: Int) : EnforcementAction
}
