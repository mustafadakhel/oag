package com.mustafadakhel.oag.enforcement

import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DataBudgetTrackerTest {
    private lateinit var tracker: DataBudgetTracker

    @BeforeTest
    fun setUp() {
        tracker = DataBudgetTracker()
    }

    @Test
    fun `recordAndCheck returns true when under limit`() {
        assertTrue(tracker.recordAndCheck("s1", "example.com", 100, 1000))
    }

    @Test
    fun `recordAndCheck returns true when exactly at limit`() {
        assertTrue(tracker.recordAndCheck("s1", "example.com", 1000, 1000))
    }

    @Test
    fun `recordAndCheck returns false when over limit`() {
        assertFalse(tracker.recordAndCheck("s1", "example.com", 1001, 1000))
    }

    @Test
    fun `recordAndCheck accumulates across calls`() {
        assertTrue(tracker.recordAndCheck("s1", "example.com", 400, 1000))
        assertTrue(tracker.recordAndCheck("s1", "example.com", 400, 1000))
        assertTrue(tracker.recordAndCheck("s1", "example.com", 200, 1000))
        assertFalse(tracker.recordAndCheck("s1", "example.com", 1, 1000))
    }

    @Test
    fun `different sessions are tracked independently`() {
        assertTrue(tracker.recordAndCheck("s1", "example.com", 900, 1000))
        assertTrue(tracker.recordAndCheck("s2", "example.com", 900, 1000))
        assertFalse(tracker.recordAndCheck("s1", "example.com", 200, 1000))
        assertTrue(tracker.recordAndCheck("s2", "example.com", 100, 1000))
    }

    @Test
    fun `different hosts are tracked independently`() {
        assertTrue(tracker.recordAndCheck("s1", "a.com", 900, 1000))
        assertTrue(tracker.recordAndCheck("s1", "b.com", 900, 1000))
        assertFalse(tracker.recordAndCheck("s1", "a.com", 200, 1000))
        assertTrue(tracker.recordAndCheck("s1", "b.com", 100, 1000))
    }

    @Test
    fun `currentUsage returns zero for unknown keys`() {
        assertEquals(0L, tracker.currentUsage("s1", "example.com"))
    }

    @Test
    fun `currentUsage reflects recorded bytes`() {
        tracker.recordAndCheck("s1", "example.com", 500, 1000)
        assertEquals(500L, tracker.currentUsage("s1", "example.com"))
        tracker.recordAndCheck("s1", "example.com", 300, 1000)
        assertEquals(800L, tracker.currentUsage("s1", "example.com"))
    }

    @Test
    fun `clear resets all usage`() {
        tracker.recordAndCheck("s1", "a.com", 500, 1000)
        tracker.recordAndCheck("s2", "b.com", 500, 1000)
        tracker.clear()
        assertEquals(0L, tracker.currentUsage("s1", "a.com"))
        assertEquals(0L, tracker.currentUsage("s2", "b.com"))
    }

    @Test
    fun `usage continues to accumulate even after exceeding limit`() {
        tracker.recordAndCheck("s1", "example.com", 1000, 500)
        assertEquals(1000L, tracker.currentUsage("s1", "example.com"))
        tracker.recordAndCheck("s1", "example.com", 200, 500)
        assertEquals(1200L, tracker.currentUsage("s1", "example.com"))
    }
}
