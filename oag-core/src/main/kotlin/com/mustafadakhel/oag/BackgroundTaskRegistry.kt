package com.mustafadakhel.oag

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

data class TaskSnapshot(
    val name: String,
    val running: Boolean,
    val successCount: Long,
    val errorCount: Long,
    val lastSuccessMs: Long?,
    val lastErrorMs: Long?,
    val lastError: String?
)

class TaskHandle internal constructor(val name: String) {
    @Volatile var running: Boolean = false
    private val successCount = AtomicLong(0)
    private val errorCount = AtomicLong(0)
    private val lastSuccessMs = AtomicLong(0)
    private val lastErrorMs = AtomicLong(0)
    private val lastError = AtomicReference<String?>(null)

    fun recordSuccess(timestampMs: Long) {
        successCount.incrementAndGet()
        lastSuccessMs.set(timestampMs)
    }

    fun recordError(timestampMs: Long, message: String?) {
        errorCount.incrementAndGet()
        lastErrorMs.set(timestampMs)
        lastError.set(message)
    }

    fun toSnapshot() = TaskSnapshot(
        name = name,
        running = running,
        successCount = successCount.get(),
        errorCount = errorCount.get(),
        lastSuccessMs = lastSuccessMs.get().takeIf { it > 0 },
        lastErrorMs = lastErrorMs.get().takeIf { it > 0 },
        lastError = lastError.get()
    )
}

class BackgroundTaskRegistry {
    private val tasks = ConcurrentHashMap<String, TaskHandle>()

    fun register(name: String): TaskHandle {
        val handle = TaskHandle(name)
        tasks[name] = handle
        return handle
    }

    fun snapshot(): List<TaskSnapshot> =
        tasks.values.sortedBy { it.name }.map { it.toSnapshot() }

    fun taskCount(): Int = tasks.size
}
