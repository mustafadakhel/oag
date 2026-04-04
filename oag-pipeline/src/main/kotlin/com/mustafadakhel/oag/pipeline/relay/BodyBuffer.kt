package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.pipeline.HEX_TOKEN_REGEX
import com.mustafadakhel.oag.pipeline.MAX_BUFFER_REQUEST_BODY_BYTES
import com.mustafadakhel.oag.pipeline.inspection.RequestBodyException
import com.mustafadakhel.oag.pipeline.readLine

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

fun readChunkedBody(clientInput: InputStream, maxBytes: Long): ByteArray? {
    val out = ByteArrayOutputStream(INITIAL_BUFFER_SIZE)
    val buf = ByteArray(INITIAL_BUFFER_SIZE)
    var totalRead = 0L

    while (true) {
        val sizeLine = try {
            readLine(clientInput) ?: return null
        } catch (_: IOException) {
            return null
        }
        val sizeToken = sizeLine.substringBefore(';').trim()
        if (!sizeToken.matches(HEX_TOKEN_REGEX)) return null
        val chunkSize = sizeToken.toLongOrNull(16) ?: return null

        if (chunkSize == 0L) {
            readLine(clientInput) // consume trailing CRLF after final chunk
            break
        }

        if (totalRead + chunkSize > maxBytes) return null

        var remaining = chunkSize
        while (remaining > 0) {
            val toRead = minOf(remaining.toInt(), buf.size)
            val read = try {
                clientInput.read(buf, 0, toRead)
            } catch (_: SocketTimeoutException) {
                throw RequestBodyException.Timeout()
            } catch (_: IOException) {
                return null
            }
            if (read == -1) return null
            out.write(buf, 0, read)
            remaining -= read
            totalRead += read
        }
        readLine(clientInput) // consume CRLF after chunk data
    }

    return if (totalRead > 0) out.toByteArray() else null
}
