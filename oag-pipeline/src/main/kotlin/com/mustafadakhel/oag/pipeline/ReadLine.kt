package com.mustafadakhel.oag.pipeline

import java.io.InputStream

fun readLine(input: InputStream): String? {
    val buffer = StringBuilder()
    var prev = -1
    while (true) {
        val b = input.read()
        if (b == -1) {
            return if (buffer.isEmpty()) null else buffer.toString()
        }
        if (b == '\n'.code && prev == '\r'.code) {
            buffer.setLength(buffer.length - 1)
            return buffer.toString()
        }
        buffer.append(b.toChar())
        require(buffer.length <= MAX_HTTP_LINE_LENGTH) { "HTTP line too long" }
        prev = b
    }
}
