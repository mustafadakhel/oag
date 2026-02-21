package com.mustafadakhel.oag.audit

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

import java.nio.file.Files
import java.nio.file.Path
import java.time.LocalDateTime
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.GZIPInputStream

class RotatingOutputStreamTest {
    private val tempDirs = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        for (dir in tempDirs) {
            runCatching {
                Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
        tempDirs.clear()
    }

    private fun tempDir(): Path = Files.createTempDirectory("rot-test").also { tempDirs.add(it) }

    @Test
    fun `writes without rotation when under max size`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val ros = RotatingOutputStream(logPath, maxSizeBytes = 1000, maxFiles = 3)
        ros.use { it.write("hello\n".toByteArray()) }
        assertEquals("hello\n", Files.readString(logPath))
        assertFalse(Files.exists(dir.resolve("audit.jsonl.1")))
    }

    @Test
    fun `rotates when write exceeds max size`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val ros = RotatingOutputStream(logPath, maxSizeBytes = 10, maxFiles = 3)
        ros.use {
            it.write("12345678\n".toByteArray()) // 9 bytes, under limit
            it.flush()
            it.write("more data\n".toByteArray()) // triggers rotation
        }
        assertTrue(Files.exists(dir.resolve("audit.jsonl.1")))
        val rotated = Files.readString(dir.resolve("audit.jsonl.1"))
        assertEquals("12345678\n", rotated)
        val current = Files.readString(logPath)
        assertEquals("more data\n", current)
    }

    @Test
    fun `shifts files on multiple rotations`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val oldest = "AAA\n"
        val middle = "BBB\n"
        val newest = "CCC\n"
        val ros = RotatingOutputStream(logPath, maxSizeBytes = 5, maxFiles = 5)
        ros.use {
            it.write(oldest.toByteArray())
            it.flush()
            it.write(middle.toByteArray())
            it.flush()
            it.write(newest.toByteArray())
        }
        assertTrue(Files.exists(dir.resolve("audit.jsonl.1")))
        assertTrue(Files.exists(dir.resolve("audit.jsonl.2")))
        assertEquals(oldest, Files.readString(dir.resolve("audit.jsonl.2")))
        assertEquals(middle, Files.readString(dir.resolve("audit.jsonl.1")))
        assertEquals(newest, Files.readString(logPath))
    }

    @Test
    fun `max files limit enforced`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val ros = RotatingOutputStream(logPath, maxSizeBytes = 5, maxFiles = 2)
        ros.use {
            it.write("AAA\n".toByteArray())
            it.flush()
            it.write("BBB\n".toByteArray()) // rotation 1
            it.flush()
            it.write("CCC\n".toByteArray()) // rotation 2
            it.flush()
            it.write("DDD\n".toByteArray()) // rotation 3 — AAA should be evicted
        }
        assertTrue(Files.exists(dir.resolve("audit.jsonl.1")))
        assertTrue(Files.exists(dir.resolve("audit.jsonl.2")))
        assertFalse(Files.exists(dir.resolve("audit.jsonl.3")))
        assertEquals("DDD\n", Files.readString(logPath))
    }

    @Test
    fun `compressed rotation creates gz files`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val ros = RotatingOutputStream(logPath, maxSizeBytes = 10, maxFiles = 3, compress = true)
        ros.use {
            it.write("12345678\n".toByteArray())
            it.flush()
            it.write("new data\n".toByteArray()) // triggers rotation with compression
        }
        assertTrue(Files.exists(dir.resolve("audit.jsonl.1.gz")))
        assertFalse(Files.exists(dir.resolve("audit.jsonl.1")))
        val decompressed = GZIPInputStream(Files.newInputStream(dir.resolve("audit.jsonl.1.gz"))).use {
            it.readBytes().decodeToString()
        }
        assertEquals("12345678\n", decompressed)
        assertEquals("new data\n", Files.readString(logPath))
    }

    @Test
    fun `compressed rotation shifts gz files`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val ros = RotatingOutputStream(logPath, maxSizeBytes = 5, maxFiles = 5, compress = true)
        ros.use {
            it.write("AA\n".toByteArray())
            it.flush()
            it.write("BB\n".toByteArray()) // rotation 1
            it.flush()
            it.write("CC\n".toByteArray()) // rotation 2
        }
        assertTrue(Files.exists(dir.resolve("audit.jsonl.1.gz")))
        assertTrue(Files.exists(dir.resolve("audit.jsonl.2.gz")))
        assertFalse(Files.exists(dir.resolve("audit.jsonl.1")))
        assertFalse(Files.exists(dir.resolve("audit.jsonl.2")))
    }

    @Test
    fun `no rotation when maxSizeBytes is zero`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val ros = RotatingOutputStream(logPath, maxSizeBytes = 0, maxFiles = 3)
        ros.use {
            it.write("unlimited data can flow without rotation\n".toByteArray())
        }
        assertFalse(Files.exists(dir.resolve("audit.jsonl.1")))
        assertTrue(Files.readString(logPath).contains("unlimited"))
    }

    @Test
    fun `single byte write triggers rotation`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val ros = RotatingOutputStream(logPath, maxSizeBytes = 3, maxFiles = 3)
        ros.use {
            it.write('A'.code)
            it.write('B'.code)
            it.write('C'.code) // 3 bytes, at limit
            it.write('D'.code) // triggers rotation
        }
        assertTrue(Files.exists(dir.resolve("audit.jsonl.1")))
        assertEquals("ABC", Files.readString(dir.resolve("audit.jsonl.1")))
        assertEquals("D", Files.readString(logPath))
    }

    @Test
    fun `write with offset and length works`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val ros = RotatingOutputStream(logPath, maxSizeBytes = 1000, maxFiles = 3)
        val data = "hello world".toByteArray()
        ros.use { it.write(data, 6, 5) } // writes "world"
        assertEquals("world", Files.readString(logPath))
    }

    @Test
    fun `time-based rotation creates period-suffixed file`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val now = AtomicReference(LocalDateTime.of(2025, 3, 7, 10, 0))
        val ros = RotatingOutputStream(
            logPath, maxSizeBytes = 0, maxFiles = 5,
            rotationInterval = RotationInterval.HOURLY,
            clock = { now.get() }
        )
        ros.use {
            it.write("hour-10\n".toByteArray())
            it.flush()
            now.set(LocalDateTime.of(2025, 3, 7, 11, 0))
            it.write("hour-11\n".toByteArray())
        }
        val rotated = dir.resolve("audit.jsonl.2025-03-07-10")
        assertTrue(Files.exists(rotated))
        assertEquals("hour-10\n", Files.readString(rotated))
        assertEquals("hour-11\n", Files.readString(logPath))
    }

    @Test
    fun `time-based rotation daily interval`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val now = AtomicReference(LocalDateTime.of(2025, 3, 7, 10, 0))
        val ros = RotatingOutputStream(
            logPath, maxSizeBytes = 0, maxFiles = 5,
            rotationInterval = RotationInterval.DAILY,
            clock = { now.get() }
        )
        ros.use {
            it.write("day1\n".toByteArray())
            it.flush()
            now.set(LocalDateTime.of(2025, 3, 8, 10, 0))
            it.write("day2\n".toByteArray())
        }
        val rotated = dir.resolve("audit.jsonl.2025-03-07")
        assertTrue(Files.exists(rotated))
        assertEquals("day1\n", Files.readString(rotated))
        assertEquals("day2\n", Files.readString(logPath))
    }

    @Test
    fun `time-based cleanup removes old files beyond maxFiles`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val now = AtomicReference(LocalDateTime.of(2025, 1, 1, 0, 0))
        val ros = RotatingOutputStream(
            logPath, maxSizeBytes = 0, maxFiles = 2,
            rotationInterval = RotationInterval.DAILY,
            clock = { now.get() }
        )
        ros.use {
            it.write("jan1\n".toByteArray()); it.flush()
            now.set(LocalDateTime.of(2025, 1, 2, 0, 0))
            it.write("jan2\n".toByteArray()); it.flush()
            now.set(LocalDateTime.of(2025, 1, 3, 0, 0))
            it.write("jan3\n".toByteArray()); it.flush()
            now.set(LocalDateTime.of(2025, 1, 4, 0, 0))
            it.write("jan4\n".toByteArray())
        }
        assertTrue(Files.exists(dir.resolve("audit.jsonl.2025-01-03")))
        assertTrue(Files.exists(dir.resolve("audit.jsonl.2025-01-02")))
        assertFalse(Files.exists(dir.resolve("audit.jsonl.2025-01-01")))
    }

    @Test
    fun `time-based rotation with compression`() {
        val dir = tempDir()
        val logPath = dir.resolve("audit.jsonl")
        val now = AtomicReference(LocalDateTime.of(2025, 6, 1, 8, 0))
        val ros = RotatingOutputStream(
            logPath, maxSizeBytes = 0, maxFiles = 5, compress = true,
            rotationInterval = RotationInterval.HOURLY,
            clock = { now.get() }
        )
        ros.use {
            it.write("data-h8\n".toByteArray())
            it.flush()
            now.set(LocalDateTime.of(2025, 6, 1, 9, 0))
            it.write("data-h9\n".toByteArray())
        }
        val gzPath = dir.resolve("audit.jsonl.2025-06-01-08.gz")
        assertTrue(Files.exists(gzPath))
        assertFalse(Files.exists(dir.resolve("audit.jsonl.2025-06-01-08")))
        val decompressed = GZIPInputStream(Files.newInputStream(gzPath)).use { it.readBytes().decodeToString() }
        assertEquals("data-h8\n", decompressed)
    }
}
