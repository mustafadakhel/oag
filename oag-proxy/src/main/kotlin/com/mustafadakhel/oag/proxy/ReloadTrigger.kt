package com.mustafadakhel.oag.proxy

internal enum class ReloadTrigger {
    SIGNAL,
    FILE_WATCHER,
    POLICY_FETCH,
    ADMIN_ENDPOINT
}

internal data class ReloadCallbackResult(
    val success: Boolean,
    val changed: Boolean,
    val newHash: String? = null,
    val errorMessage: String? = null
)
