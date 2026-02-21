package com.mustafadakhel.oag

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BackoffStrategyTest {

    @Test
    fun `fixed strategy returns constant delay`() {
        val strategy = BackoffStrategy.fixed(500)
        assertEquals(500, strategy.delayMs(1))
        assertEquals(500, strategy.delayMs(5))
        assertEquals(500, strategy.delayMs(100))
    }

    @Test
    fun `exponential strategy doubles by default`() {
        val strategy = BackoffStrategy.exponential(baseMs = 100, multiplier = 2.0, maxMs = 10000)
        assertEquals(100, strategy.delayMs(1))
        assertEquals(200, strategy.delayMs(2))
        assertEquals(400, strategy.delayMs(3))
    }

    @Test
    fun `exponential strategy caps at maxMs`() {
        val strategy = BackoffStrategy.exponential(baseMs = 1000, multiplier = 10.0, maxMs = 5000)
        assertEquals(1000, strategy.delayMs(1))
        assertEquals(5000, strategy.delayMs(2))
        assertEquals(5000, strategy.delayMs(10))
    }

    @Test
    fun `exponential with jitter adds randomness`() {
        val strategy = BackoffStrategy.exponential(baseMs = 100, jitterFactor = 0.5)
        val delays = (1..100).map { strategy.delayMs(1) }
        assertTrue(delays.distinct().size > 1, "Jitter should produce varied delays")
        assertTrue(delays.all { it in 100..150 }, "Delays should be in [100, 150] range")
    }

    @Test
    fun `fun interface allows custom implementation`() {
        val custom = BackoffStrategy { attempt -> attempt * 100L }
        assertEquals(100, custom.delayMs(1))
        assertEquals(300, custom.delayMs(3))
    }
}
