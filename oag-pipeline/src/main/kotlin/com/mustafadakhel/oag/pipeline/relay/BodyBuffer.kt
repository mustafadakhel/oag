package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.pipeline.MAX_BUFFER_REQUEST_BODY_BYTES
import com.mustafadakhel.oag.pipeline.inspection.RequestBodyException

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.SocketTimeoutException

private const val INITIAL_BUFFER_SIZE = 8192

fun bufferRequestBody(clientInput: InputStream, contentLength: Long): ByteArray {
    require(contentLength in 0..MAX_BUFFER_REQUEST_BODY_BYTES) {
        "Request body too large: $contentLength bytes (max $MAX_BUFFER_REQUEST_BODY_BYTES)"
    }
    val expectedSize = contentLength.toInt()
    val initialSize = minOf(expectedSize, INITIAL_BUFFER_SIZE)
    val out = ByteArrayOutputStream(initialSize)
    val chunk = ByteArray(minOf(expectedSize, INITIAL_BUFFER_SIZE))
    var totalRead = 0
    while (totalRead < expectedSize) {
        val toRead = minOf(chunk.size, expectedSize - totalRead)
        val read = try {
            clientInput.read(chunk, 0, toRead)
        } catch (error: SocketTimeoutException) {
            throw RequestBodyException.Timeout()
        } catch (error: IOException) {
            throw RequestBodyException.ReadFailure()
        }
        if (read == -1) break
        out.write(chunk, 0, read)
        totalRead += read
    }
    if (totalRead != expectedSize) throw RequestBodyException.Truncated()
    return out.toByteArray()
}
