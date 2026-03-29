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

package com.mustafadakhel.oag.pipeline

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserTurnExtractorTest {

    @Test
    fun `standard OpenAI chat format extracts last user message`() {
        val body = """{"messages":[{"role":"user","content":"Hello"}]}"""
        assertEquals("Hello", extractUserTurnText(body))
    }

    @Test
    fun `multi-turn conversation extracts last user message`() {
        val body = """{"messages":[{"role":"user","content":"First"},{"role":"assistant","content":"Reply"},{"role":"user","content":"Second"}]}"""
        assertEquals("Second", extractUserTurnText(body))
    }

    @Test
    fun `no user role in messages returns null`() {
        val body = """{"messages":[{"role":"assistant","content":"Reply"},{"role":"system","content":"System"}]}"""
        assertNull(extractUserTurnText(body))
    }

    @Test
    fun `empty messages array returns null`() {
        val body = """{"messages":[]}"""
        assertNull(extractUserTurnText(body))
    }

    @Test
    fun `non-JSON input returns null`() {
        assertNull(extractUserTurnText("not json at all"))
    }

    @Test
    fun `multimodal content concatenates text parts ignores image parts`() {
        val body = """{"messages":[{"role":"user","content":[{"type":"text","text":"Hello"},{"type":"image_url","image_url":{"url":"data:..."}},{"type":"text","text":"World"}]}]}"""
        assertEquals("Hello\nWorld", extractUserTurnText(body))
    }

    @Test
    fun `messages array over 100 elements respects iteration cap`() {
        val msgs = (1..150).joinToString(",") { """{"role":"assistant","content":"msg$it"}""" }
        val body = """{"messages":[$msgs,{"role":"user","content":"found"}]}"""
        // user message is at index 150 (last element) — within last 100
        assertEquals("found", extractUserTurnText(body))
    }

    @Test
    fun `non-chat JSON with no messages key returns null`() {
        val body = """{"model":"gpt-4","prompt":"hello"}"""
        assertNull(extractUserTurnText(body))
    }

    @Test
    fun `malformed message entry gracefully skipped`() {
        val body = """{"messages":["not-an-object",{"role":"user","content":"ok"}]}"""
        assertEquals("ok", extractUserTurnText(body))
    }

    @Test
    fun `user message with null content returns null`() {
        val body = """{"messages":[{"role":"user","content":null}]}"""
        assertNull(extractUserTurnText(body))
    }
}
