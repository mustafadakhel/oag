package com.mustafadakhel.oag

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BackgroundTaskRegistryTest {

    @Test
    fun `register creates a handle with the given name`() {
        val registry = BackgroundTaskRegistry()
        val handle = registry.register("my_task")
        assertEquals("my_task", handle.name)
        assertFalse(handle.running)
    }

    @Test
    fun `taskCount reflects number of registered tasks`() {
        val registry = BackgroundTaskRegistry()
        assertEquals(0, registry.taskCount())
        registry.register("a")
        assertEquals(1, registry.taskCount())
        registry.register("b")
        assertEquals(2, registry.taskCount())
    }

    @Test
    fun `snapshot returns sorted list of task snapshots`() {
        val registry = BackgroundTaskRegistry()
        registry.register("zebra")
        registry.register("alpha")
        val snapshots = registry.snapshot()
        assertEquals(2, snapshots.size)
        assertEquals("alpha", snapshots[0].name)
        assertEquals("zebra", snapshots[1].name)
    }

    @Test
    fun `handle records success`() {
        val registry = BackgroundTaskRegistry()
        val handle = registry.register("task")
        handle.recordSuccess(1000L)
        handle.recordSuccess(2000L)
        val snapshot = registry.snapshot().single()
        assertEquals(2, snapshot.successCount)
        assertEquals(2000L, snapshot.lastSuccessMs)
        assertEquals(0, snapshot.errorCount)
        assertNull(snapshot.lastErrorMs)
    }

    @Test
    fun `handle records errors`() {
        val registry = BackgroundTaskRegistry()
        val handle = registry.register("task")
        handle.recordError(1000L, "first failure")
        handle.recordError(2000L, "second failure")
        val snapshot = registry.snapshot().single()
        assertEquals(2, snapshot.errorCount)
        assertEquals(2000L, snapshot.lastErrorMs)
        assertEquals("second failure", snapshot.lastError)
        assertEquals(0, snapshot.successCount)
        assertNull(snapshot.lastSuccessMs)
    }

    @Test
    fun `handle tracks running state`() {
        val registry = BackgroundTaskRegistry()
        val handle = registry.register("task")
        assertFalse(handle.running)
        handle.running = true
        assertTrue(registry.snapshot().single().running)
        handle.running = false
        assertFalse(registry.snapshot().single().running)
    }

    @Test
    fun `snapshot returns empty list when no tasks registered`() {
        val registry = BackgroundTaskRegistry()
        assertTrue(registry.snapshot().isEmpty())
    }

    @Test
    fun `lastSuccessMs and lastErrorMs are null when no events recorded`() {
        val registry = BackgroundTaskRegistry()
        registry.register("task")
        val snapshot = registry.snapshot().single()
        assertNull(snapshot.lastSuccessMs)
        assertNull(snapshot.lastErrorMs)
        assertNull(snapshot.lastError)
    }

    @Test
    fun `re-registering same name replaces handle`() {
        val registry = BackgroundTaskRegistry()
        val first = registry.register("task")
        first.recordSuccess(1000L)
        val second = registry.register("task")
        assertEquals(1, registry.taskCount())
        val snapshot = registry.snapshot().single()
        assertEquals(0, snapshot.successCount)
        assertNull(snapshot.lastSuccessMs)
    }
}
