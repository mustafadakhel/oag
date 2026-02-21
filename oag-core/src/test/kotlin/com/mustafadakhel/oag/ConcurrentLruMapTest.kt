package com.mustafadakhel.oag

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ConcurrentLruMapTest {

    @Test
    fun `get returns null for missing key`() {
        val map = ConcurrentLruMap<String, Int>(10)
        assertNull(map.get("missing"))
    }

    @Test
    fun `put and get round-trip`() {
        val map = ConcurrentLruMap<String, Int>(10)
        map.put("a", 1)
        assertEquals(1, map.get("a"))
    }

    @Test
    fun `getOrPut returns existing value`() {
        val map = ConcurrentLruMap<String, Int>(10)
        map.put("a", 1)
        val result = map.getOrPut("a") { 99 }
        assertEquals(1, result)
    }

    @Test
    fun `getOrPut computes on miss`() {
        val map = ConcurrentLruMap<String, Int>(10)
        val result = map.getOrPut("a") { 42 }
        assertEquals(42, result)
        assertEquals(42, map.get("a"))
    }

    @Test
    fun `remove deletes entry`() {
        val map = ConcurrentLruMap<String, Int>(10)
        map.put("a", 1)
        assertEquals(1, map.remove("a"))
        assertNull(map.get("a"))
    }

    @Test
    fun `remove returns null for missing key`() {
        val map = ConcurrentLruMap<String, Int>(10)
        assertNull(map.remove("missing"))
    }

    @Test
    fun `clear removes all entries`() {
        val map = ConcurrentLruMap<String, Int>(10)
        map.put("a", 1)
        map.put("b", 2)
        map.clear()
        assertEquals(0, map.size())
    }

    @Test
    fun `size tracks entry count`() {
        val map = ConcurrentLruMap<String, Int>(10)
        assertEquals(0, map.size())
        map.put("a", 1)
        assertEquals(1, map.size())
        map.put("b", 2)
        assertEquals(2, map.size())
    }

    @Test
    fun `evicts eldest when exceeding max size`() {
        val map = ConcurrentLruMap<String, Int>(3)
        map.put("a", 1)
        map.put("b", 2)
        map.put("c", 3)
        map.put("d", 4)
        assertEquals(3, map.size())
        assertNull(map.get("a"))
        assertEquals(2, map.get("b"))
        assertEquals(4, map.get("d"))
    }

    @Test
    fun `LRU access order prevents eviction of recently accessed`() {
        val map = ConcurrentLruMap<String, Int>(3)
        map.put("a", 1)
        map.put("b", 2)
        map.put("c", 3)
        map.get("a") // access "a" to make it recently used
        map.put("d", 4) // should evict "b" (least recently used)
        assertEquals(1, map.get("a"))
        assertNull(map.get("b"))
        assertEquals(3, map.get("c"))
        assertEquals(4, map.get("d"))
    }

    @Test
    fun `compute updates existing value`() {
        val map = ConcurrentLruMap<String, Long>(10)
        map.put("a", 5L)
        val result = map.compute("a") { current -> (current ?: 0L) + 10L }
        assertEquals(15L, result)
        assertEquals(15L, map.get("a"))
    }

    @Test
    fun `compute creates new value`() {
        val map = ConcurrentLruMap<String, Long>(10)
        val result = map.compute("a") { current -> (current ?: 0L) + 10L }
        assertEquals(10L, result)
    }

    @Test
    fun `compute removes entry when remapping returns null`() {
        val map = ConcurrentLruMap<String, Long>(10)
        map.put("a", 5L)
        val result = map.compute("a") { null }
        assertNull(result)
        assertNull(map.get("a"))
    }

    @Test
    fun `withLock provides atomic multi-step operations`() {
        val map = ConcurrentLruMap<String, Int>(10)
        map.put("a", 1)
        map.put("b", 2)
        val sum = map.withLock {
            val a = this["a"] ?: 0
            val b = this["b"] ?: 0
            a + b
        }
        assertEquals(3, sum)
    }

    @Test
    fun `withLock supports clear and repopulate atomically`() {
        val map = ConcurrentLruMap<String, Int>(10)
        map.put("a", 1)
        map.withLock {
            clear()
            this["x"] = 10
            this["y"] = 20
        }
        assertNull(map.get("a"))
        assertEquals(10, map.get("x"))
        assertEquals(20, map.get("y"))
    }

    @Test
    fun `concurrent access does not corrupt state`() {
        val map = ConcurrentLruMap<String, Long>(1000)
        val threads = (1..10).map { threadId ->
            Thread {
                repeat(1000) { i ->
                    val key = "key-${i % 100}"
                    map.compute(key) { current -> (current ?: 0L) + 1L }
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        val totalSum = (0 until 100).sumOf { map.get("key-$it") ?: 0L }
        assertEquals(10_000L, totalSum)
    }
}
