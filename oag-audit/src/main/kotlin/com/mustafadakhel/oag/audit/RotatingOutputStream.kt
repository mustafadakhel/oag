package com.mustafadakhel.oag.audit

import com.mustafadakhel.oag.BYTES_PER_MB
import com.mustafadakhel.oag.IO_BUFFER_SIZE
import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.label

import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.zip.GZIPOutputStream

enum class RotationInterval {
    HOURLY,
    DAILY;

    fun periodKey(time: LocalDateTime): String = when (this) {
        HOURLY -> time.format(HOURLY_FORMATTER)
        DAILY -> time.format(DAILY_FORMATTER)
    }

    companion object {
        private val HOURLY_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd-HH")
        private val DAILY_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd")

        fun from(value: String?): RotationInterval? =
            entries.firstOrNull { it.label() == value?.trim()?.lowercase(Locale.ROOT) }
    }
}

private val NUMBERED_ROTATION_PATTERN = Regex(""".*\.\d+(\.gz)?$""")
private const val MAX_STALE_SCAN = 20

class RotatingOutputStream(
    private val logPath: Path,
    private val maxSizeBytes: Long,
    private val maxFiles: Int = 5,
    private val compress: Boolean = false,
    private val rotationInterval: RotationInterval? = null,
    private val onError: (String) -> Unit = System.err::println,
    private val clock: () -> LocalDateTime = LocalDateTime::now
) : OutputStream() {
    private val lock = Any()
    private var currentStream: FileOutputStream = openAppend()
    private var currentSize: Long = if (Files.exists(logPath)) Files.size(logPath) else 0L
    private var currentPeriod: String? = rotationInterval?.periodKey(clock())

    override fun write(b: Int) {
        val toCompress = synchronized(lock) {
            checkRotate(1).also {
                currentStream.write(b)
                currentSize += 1
            }
        }
        toCompress?.let(::compressFile)
    }

    override fun write(b: ByteArray) {
        val toCompress = synchronized(lock) {
            checkRotate(b.size.toLong()).also {
                currentStream.write(b)
                currentSize += b.size
            }
        }
        toCompress?.let(::compressFile)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        val toCompress = synchronized(lock) {
            checkRotate(len.toLong()).also {
                currentStream.write(b, off, len)
                currentSize += len
            }
        }
        toCompress?.let(::compressFile)
    }

    override fun flush() {
        synchronized(lock) {
            currentStream.flush()
        }
    }

    override fun close() {
        synchronized(lock) {
            currentStream.close()
        }
    }

    private fun checkRotate(pendingBytes: Long): Path? {
        if (rotationInterval != null) {
            val now = rotationInterval.periodKey(clock())
            if (now != currentPeriod) {
                return rotateByTime(now)
            }
        }
        if (maxSizeBytes <= 0) return null
        if (currentSize + pendingBytes <= maxSizeBytes) return null
        return rotate()
    }

    private fun rotate(): Path? {
        shiftFiles()
        val rotatedPath = rotatedPath(1)
        val moved = closeAndMove(rotatedPath, "log rotation")
        currentStream = openAppend()
        currentSize = if (moved) 0L else (try { Files.size(logPath) } catch (_: IOException) { 0L })
        return rotatedPath.takeIf { moved && compress }
    }

    private fun rotateByTime(newPeriod: String): Path? {
        val suffix = currentPeriod ?: newPeriod
        val rotatedPath = logPath.resolveSibling("${logPath.fileName}.$suffix")
        val moved = closeAndMove(rotatedPath, "log time rotation")
        currentPeriod = newPeriod
        currentStream = openAppend()
        currentSize = 0L
        cleanupOldTimedFiles()
        return rotatedPath.takeIf { moved && compress }
    }

    private fun closeAndMove(target: Path, context: String): Boolean {
        currentStream.flush()
        val oldStream = currentStream
        return runCatching {
            oldStream.close()
            Files.move(logPath, target, StandardCopyOption.REPLACE_EXISTING)
        }.onFailure { e ->
            onError("${LOG_PREFIX}$context move failed: ${e.message}")
        }.isSuccess
    }

    private fun cleanupOldTimedFiles() {
        if (maxFiles <= 0) return
        val parent = logPath.parent ?: return
        val prefix = "${logPath.fileName}."
        val timedFiles = try {
            Files.list(parent).use { it.toList() }
                .filter { path ->
                    val name = path.fileName.toString()
                    name.startsWith(prefix) && name != logPath.fileName.toString() &&
                        !name.matches(NUMBERED_ROTATION_PATTERN)
                }
                .sortedDescending()
        } catch (e: IOException) {
            onError("${LOG_PREFIX}cleanup old timed files failed: ${e.message}")
            return
        }
        if (timedFiles.size > maxFiles) {
            timedFiles.drop(maxFiles).forEach { runCatching { Files.deleteIfExists(it) } }
        }
    }

    private fun shiftFiles() {
        val oldestPath = if (compress) Path.of("${rotatedPath(maxFiles)}.gz") else rotatedPath(maxFiles)
        if (Files.exists(oldestPath)) {
            Files.deleteIfExists(oldestPath)
        }
        if (compress) Files.deleteIfExists(rotatedPath(maxFiles))

        for (i in maxFiles - 1 downTo 1) {
            val fromPath = if (compress) Path.of("${rotatedPath(i)}.gz") else rotatedPath(i)
            val toPath = if (compress) Path.of("${rotatedPath(i + 1)}.gz") else rotatedPath(i + 1)
            if (Files.exists(fromPath)) {
                Files.move(fromPath, toPath, StandardCopyOption.REPLACE_EXISTING)
            }
            if (compress) Files.deleteIfExists(rotatedPath(i))
        }

        for (i in maxFiles + 1..maxFiles + MAX_STALE_SCAN) {
            val gone1 = !Files.deleteIfExists(rotatedPath(i))
            val gone2 = !Files.deleteIfExists(Path.of("${rotatedPath(i)}.gz"))
            if (gone1 && gone2) break
        }
    }

    private fun compressFile(source: Path) {
        if (!Files.exists(source)) return
        val gzPath = Path.of("${source}.gz")
        try {
            Files.newInputStream(source).use { input ->
                GZIPOutputStream(Files.newOutputStream(gzPath)).use { gzOut ->
                    input.copyTo(gzOut, bufferSize = IO_BUFFER_SIZE)
                }
            }
            Files.deleteIfExists(source)
        } catch (e: IOException) {
            onError("${LOG_PREFIX}log compression failed: ${e.message}")
            runCatching { Files.deleteIfExists(gzPath) }
        }
    }

    private fun rotatedPath(index: Int): Path =
        logPath.resolveSibling("${logPath.fileName}.$index")

    private fun openAppend(): FileOutputStream {
        logPath.parent?.let(Files::createDirectories)
        return FileOutputStream(logPath.toFile(), true)
    }
}

fun buildAuditOutputStream(
    logPath: String?,
    maxSizeMb: Int,
    maxFiles: Int,
    compress: Boolean,
    rotationInterval: String?,
    onError: (String) -> Unit
): OutputStream {
    val interval = rotationInterval?.let {
        requireNotNull(RotationInterval.from(it)) { "Invalid log-rotation-interval: $it (use hourly or daily)" }
    }
    return when {
        logPath != null && (maxSizeMb > 0 || interval != null) ->
            RotatingOutputStream(
                logPath = Path.of(logPath),
                maxSizeBytes = maxSizeMb.toLong() * BYTES_PER_MB,
                maxFiles = maxFiles,
                compress = compress,
                rotationInterval = interval,
                onError = onError
            )
        logPath != null -> {
            Path.of(logPath).parent?.let { Files.createDirectories(it) }
            FileOutputStream(logPath, true)
        }
        else -> System.out
    }
}
