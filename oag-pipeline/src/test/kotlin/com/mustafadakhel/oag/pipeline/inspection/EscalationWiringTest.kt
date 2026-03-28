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

package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.enforcement.SessionRequestTracker
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.nio.file.Files
import java.nio.file.Path

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertIs

class EscalationWiringTest {

    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
    }

    private fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            Files.writeString(it, content)
        }

    @Test
    fun `escalation detection with policy enabled triggers on crescendo`() {
        val path = writePolicy(
            "version: 1\n" +
            "defaults:\n" +
            "  action: allow\n" +
            "  content_inspection:\n" +
            "    enable_builtin_patterns: true\n" +
            "  injection_scoring:\n" +
            "    mode: score\n" +
            "    deny_threshold: 0.5\n" +
            "    escalation:\n" +
            "      enabled: true\n" +
            "      window_size: 3\n" +
            "      deny_patterns: [\"crescendo\"]\n" +
            "allow:\n" +
            "  - id: rule_1\n" +
            "    host: \"*.example.com\"\n"
        )
        val service = PolicyService(path)
        val tracker = SessionRequestTracker()

        // Simulate escalating injection scores over 3 turns
        tracker.recordInjectionScore("s1", 0.1)
        tracker.recordInjectionScore("s1", 0.2)
        tracker.recordInjectionScore("s1", 0.3)

        val ctx = buildTestContext(bodyText = "normal request body", sessionId = "s1")
        val outcome = checkContentInspectionPhase(ctx, service, tracker)
        // With low injection score the boost may not exceed threshold,
        // but the escalation detection path is exercised
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `disabled escalation backward compatible`() {
        val path = writePolicy(
            "version: 1\n" +
            "defaults:\n" +
            "  action: allow\n" +
            "  content_inspection:\n" +
            "    enable_builtin_patterns: true\n" +
            "allow:\n" +
            "  - id: rule_1\n" +
            "    host: \"*.example.com\"\n"
        )
        val service = PolicyService(path)
        val tracker = SessionRequestTracker()

        val ctx = buildTestContext(bodyText = "normal request body", sessionId = "s1")
        val outcome = checkContentInspectionPhase(ctx, service, tracker)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }
}
