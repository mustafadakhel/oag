package com.mustafadakhel.oag

import kotlin.math.min
import kotlin.random.Random

fun interface BackoffStrategy {
    fun delayMs(attempt: Int): Long

    companion object {
        fun fixed(delayMs: Long): BackoffStrategy =
            BackoffStrategy { delayMs }

        fun exponential(
            baseMs: Long = 100,
            multiplier: Double = 2.0,
            maxMs: Long = 30_000,
            jitterFactor: Double = 0.0
        ): BackoffStrategy = BackoffStrategy { attempt ->
            val raw = baseMs * Math.pow(multiplier, (attempt - 1).coerceAtLeast(0).toDouble())
            val capped = min(raw.toLong(), maxMs)
            if (jitterFactor > 0.0) {
                val jitter = (capped * jitterFactor * Random.nextDouble()).toLong()
                capped + jitter
            } else capped
        }
    }
}
