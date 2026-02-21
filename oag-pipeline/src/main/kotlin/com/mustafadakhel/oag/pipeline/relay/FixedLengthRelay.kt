package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.IO_BUFFER_SIZE
import com.mustafadakhel.oag.LOG_PREFIX

import java.io.InputStream
import java.io.OutputStream

fun relayFixedLengthResponse(
    upstreamIn: InputStream,
    clientOutput: OutputStream,
    contentLength: Long,
    onError: (String) -> Unit = defaultRelayErrorHandler
): Long {
    if (contentLength == 0L) {
        clientOutput.flush()
        return 0L
    }
    val total = relayExactBytes(upstreamIn, clientOutput, contentLength, onError)
    clientOutput.flush()
    return total
}

internal val defaultRelayErrorHandler: (String) -> Unit = { msg -> System.err.println("${LOG_PREFIX}$msg") }

fun relayExactBytes(
    upstreamIn: InputStream,
    clientOutput: OutputStream,
    length: Long,
    onError: (String) -> Unit = defaultRelayErrorHandler
): Long {
    val total = relayBytes(upstreamIn, clientOutput, length) { e ->
        onError("relay read failed total=$length: ${e.message}")
        -1
    }
    require(total == length) { "Truncated fixed-length body" }
    return total
}

/**
 * Shared relay core: copies exactly [count] bytes from [input] to [output].
 * [onReadError] handles I/O errors — return -1 to break the loop, or throw to propagate.
 */
fun relayBytes(
    input: InputStream,
    output: OutputStream,
    count: Long,
    onReadError: (Exception) -> Int
): Long {
    var remaining = count
    val buffer = ByteArray(IO_BUFFER_SIZE)
    var total = 0L
    while (remaining > 0) {
        val read = try {
            input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
        } catch (e: Exception) {
            onReadError(e)
        }
        if (read == -1) break
        output.write(buffer, 0, read)
        remaining -= read
        total += read
    }
    return total
}

fun relayResponse(upstreamIn: InputStream, clientOutput: OutputStream): Long {
    val buffer = ByteArray(IO_BUFFER_SIZE)
    var total = 0L
    while (true) {
        val read = upstreamIn.read(buffer)
        if (read == -1) break
        clientOutput.write(buffer, 0, read)
        total += read
    }
    clientOutput.flush()
    return total
}
