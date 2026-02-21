package com.mustafadakhel.oag

import kotlinx.coroutines.delay
import kotlin.coroutines.cancellation.CancellationException

data class RetryPolicy(
    val maxAttempts: Int = 3,
    val baseDelayMs: Long = 500L,
    val maxDelayMs: Long = Long.MAX_VALUE,
    val multiplier: Double = 2.0,
    val backoffStrategy: BackoffStrategy = BackoffStrategy.exponential(
        baseMs = baseDelayMs,
        multiplier = multiplier,
        maxMs = maxDelayMs
    )
)

class RetryExhaustedException(
    val lastError: Exception,
    val attempts: Int
) : RuntimeException("retry exhausted after $attempts attempts", lastError)

inline fun <T> withRetry(
    policy: RetryPolicy,
    onFailure: (attempt: Int, error: Exception) -> Unit = { _, _ -> },
    block: () -> T
): T {
    var lastError: Exception? = null
    repeat(policy.maxAttempts) { index ->
        try {
            return block()
        } catch (e: Exception) {
            if (e is InterruptedException) {
                Thread.currentThread().interrupt()
                throw e
            }
            lastError = e
            onFailure(index + 1, e)
            if (index < policy.maxAttempts - 1) {
                Thread.sleep(policy.backoffStrategy.delayMs(index + 1))
            }
        }
    }
    throw RetryExhaustedException(requireNotNull(lastError), policy.maxAttempts)
}

suspend fun <T> withSuspendRetry(
    policy: RetryPolicy,
    onFailure: (attempt: Int, error: Exception) -> Unit = { _, _ -> },
    block: suspend () -> T
): T {
    var lastError: Exception? = null
    repeat(policy.maxAttempts) { index ->
        try {
            return block()
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            lastError = e
            onFailure(index + 1, e)
            if (index < policy.maxAttempts - 1) {
                delay(policy.backoffStrategy.delayMs(index + 1))
            }
        }
    }
    throw RetryExhaustedException(requireNotNull(lastError), policy.maxAttempts)
}
