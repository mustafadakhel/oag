package com.mustafadakhel.oag.proxy.lifecycle

import com.mustafadakhel.oag.BackgroundTaskRegistry
import com.mustafadakhel.oag.TaskHandle

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

internal fun launchTrackedPeriodic(
    scope: CoroutineScope,
    registry: BackgroundTaskRegistry,
    name: String,
    intervalMs: Long,
    block: suspend () -> Unit
) {
    val handle = registry.register(name)
    handle.running = true
    scope.launch {
        try {
            while (isActive) {
                delay(intervalMs)
                executeTrackedBlock(handle, block)
            }
        } finally {
            handle.running = false
        }
    }
}

private suspend fun executeTrackedBlock(
    handle: TaskHandle,
    block: suspend () -> Unit
) {
    try {
        block()
        handle.recordSuccess(System.currentTimeMillis())
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        handle.recordError(System.currentTimeMillis(), e.message)
    }
}
