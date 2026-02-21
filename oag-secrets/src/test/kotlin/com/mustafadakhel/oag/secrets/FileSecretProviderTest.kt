package com.mustafadakhel.oag.secrets

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

import java.nio.file.Files
import java.nio.file.Path

class FileSecretProviderTest {
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

    private fun tempDir(): Path = Files.createTempDirectory("oag-secrets").also { tempDirs.add(it) }

    @Test
    fun `file provider resolves secret value and version`() {
        val dir = tempDir()
        Files.writeString(dir.resolve("API_KEY.secret"), "sekret\n")
        Files.writeString(dir.resolve("API_KEY.secret.version"), "v1\n")

        val provider = FileSecretProvider(dir)
        val resolved = provider.resolve("API_KEY")

        requireNotNull(resolved)
        assertEquals("sekret", resolved.value)
        assertEquals("v1", resolved.version)
    }

    @Test
    fun `file provider returns null when secret file missing`() {
        val dir = tempDir()
        val provider = FileSecretProvider(dir)

        assertNull(provider.resolve("MISSING_KEY"))
    }

    @Test
    fun `file provider rejects path traversal via dot-dot`() {
        val dir = tempDir()
        val parent = dir.parent
        requireNotNull(parent)
        Files.writeString(parent.resolve("ESCAPED.secret"), "leaked")

        val provider = FileSecretProvider(dir)
        assertNull(provider.resolve("../ESCAPED"))
    }
}
