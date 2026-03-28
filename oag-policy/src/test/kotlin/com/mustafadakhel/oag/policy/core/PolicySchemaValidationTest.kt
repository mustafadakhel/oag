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

package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.policy.distribution.policyYaml

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PolicySchemaValidationTest {

    @Test
    fun `YAML round-trip preserves all fields`() {
        val original = PolicySchemaValidation(
            schema = """{"type":"object"}""",
            onFail = "block",
            extractPath = "/choices/0/message/content",
            parseExtractedJson = true
        )
        val yaml = policyYaml.encodeToString(PolicySchemaValidation.serializer(), original)
        val decoded = policyYaml.decodeFromString(PolicySchemaValidation.serializer(), yaml)
        assertEquals(original, decoded)
    }

    @Test
    fun `YAML deserialization with minimal fields`() {
        val yaml = """
            schema: '{"type":"string"}'
        """.trimIndent()
        val result = policyYaml.decodeFromString(PolicySchemaValidation.serializer(), yaml)
        assertEquals("""{"type":"string"}""", result.schema)
        assertNull(result.onFail)
        assertNull(result.extractPath)
        assertNull(result.parseExtractedJson)
    }

    @Test
    fun `defaults are all null`() {
        val config = PolicySchemaValidation()
        assertNull(config.schema)
        assertNull(config.onFail)
        assertNull(config.extractPath)
        assertNull(config.parseExtractedJson)
    }

    @Test
    fun `YAML serialization uses snake_case field names`() {
        val config = PolicySchemaValidation(onFail = "pass", extractPath = "/a", parseExtractedJson = false)
        val yaml = policyYaml.encodeToString(PolicySchemaValidation.serializer(), config)
        assertTrue("on_fail" in yaml)
        assertTrue("extract_path" in yaml)
        assertTrue("parse_extracted_json" in yaml)
    }
}
