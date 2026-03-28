/*
 * Copyright 2026 Mustafa Dakhel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mustafadakhel.oag

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class JsonPointerTest {

    private val json = Json.parseToJsonElement("""
        {
            "choices": [
                {"message": {"content": "Hello world"}},
                {"message": {"content": "Second"}}
            ],
            "a~b": "tilde",
            "c/d": "slash"
        }
    """.trimIndent())

    @Test
    fun `empty pointer returns root`() {
        assertEquals(json, extractJsonPointer(json, ""))
    }

    @Test
    fun `extracts nested object field`() {
        val result = extractJsonPointer(json, "/choices/0/message/content")
        assertNotNull(result)
        assertEquals("Hello world", result.jsonPrimitive.content)
    }

    @Test
    fun `extracts array element by index`() {
        val result = extractJsonPointer(json, "/choices/1/message/content")
        assertNotNull(result)
        assertEquals("Second", result.jsonPrimitive.content)
    }

    @Test
    fun `missing key returns null`() {
        assertNull(extractJsonPointer(json, "/nonexistent"))
    }

    @Test
    fun `out of bounds index returns null`() {
        assertNull(extractJsonPointer(json, "/choices/99"))
    }

    @Test
    fun `negative index returns null`() {
        assertNull(extractJsonPointer(json, "/choices/-1"))
    }

    @Test
    fun `tilde escape ~0 resolves tilde in key`() {
        val result = extractJsonPointer(json, "/a~0b")
        assertNotNull(result)
        assertEquals("tilde", result.jsonPrimitive.content)
    }

    @Test
    fun `slash escape ~1 resolves slash in key`() {
        val result = extractJsonPointer(json, "/c~1d")
        assertNotNull(result)
        assertEquals("slash", result.jsonPrimitive.content)
    }

    @Test
    fun `pointer without leading slash returns null`() {
        assertNull(extractJsonPointer(json, "choices/0"))
    }

    @Test
    fun `validateJsonPointer accepts empty string`() {
        assertNull(validateJsonPointer(""))
    }

    @Test
    fun `validateJsonPointer accepts valid pointer`() {
        assertNull(validateJsonPointer("/choices/0/message"))
    }

    @Test
    fun `validateJsonPointer rejects missing leading slash`() {
        assertNotNull(validateJsonPointer("choices/0"))
    }

    @Test
    fun `validateJsonPointer rejects overly long pointer`() {
        val long = "/" + "a".repeat(600)
        assertNotNull(validateJsonPointer(long))
    }
}
