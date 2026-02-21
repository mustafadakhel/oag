package com.mustafadakhel.oag

import java.io.InputStream

const val IO_BUFFER_SIZE = 8192

fun readFully(input: InputStream, buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): Boolean {
    var pos = offset
    val end = offset + length
    while (pos < end) {
        val read = input.read(buf, pos, end - pos)
        if (read == -1) return false
        pos += read
    }
    return true
}
