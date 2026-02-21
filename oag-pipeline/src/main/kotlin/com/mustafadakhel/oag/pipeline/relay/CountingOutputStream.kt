package com.mustafadakhel.oag.pipeline.relay

import java.io.OutputStream

class CountingOutputStream(
    private val delegate: OutputStream
) : OutputStream() {
    var bytesWritten: Long = 0
        private set

    override fun write(b: Int) {
        delegate.write(b)
        bytesWritten += 1
    }

    override fun write(b: ByteArray) {
        delegate.write(b)
        bytesWritten += b.size
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        delegate.write(b, off, len)
        bytesWritten += len
    }

    override fun flush() = delegate.flush()

    override fun close() = delegate.close()
}
