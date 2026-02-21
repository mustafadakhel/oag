package com.mustafadakhel.oag.proxy.http

import com.mustafadakhel.oag.IO_BUFFER_SIZE
import com.mustafadakhel.oag.LOG_PREFIX

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

import java.io.InputStream
import java.io.OutputStream

fun CoroutineScope.startRelay(
    input: InputStream,
    output: OutputStream,
    onError: (String) -> Unit = { msg -> System.err.println("${LOG_PREFIX}$msg") }
): Job =
    launch(Dispatchers.IO) {
        val buffer = ByteArray(IO_BUFFER_SIZE)
        try {
            while (isActive) {
                val read = runCatching { input.read(buffer) }.getOrElse { e ->
                    onError("stream relay read failed: ${e.message}")
                    break
                }
                if (read == -1) break
                output.write(buffer, 0, read)
                output.flush()
            }
        } finally {
            runCatching { output.flush() }.onFailure { e ->
                onError("stream relay flush failed: ${e.message}")
            }
        }
    }
