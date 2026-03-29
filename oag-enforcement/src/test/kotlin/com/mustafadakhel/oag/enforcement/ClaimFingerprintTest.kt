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

package com.mustafadakhel.oag.enforcement

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ClaimFingerprintTest {

    @Test
    fun `extractClaimFingerprints finds URLs`() {
        val claims = extractClaimFingerprints("Visit https://example.com/docs for info")
        assertTrue(claims.any { it.key.startsWith("url:") })
    }

    @Test
    fun `extractClaimFingerprints finds version strings`() {
        val claims = extractClaimFingerprints("Python 3.12.1 is the latest")
        assertTrue(claims.any { it.key.startsWith("version:") })
        assertTrue(claims.values.any { it == "3.12.1" })
    }

    @Test
    fun `extractClaimFingerprints finds numeric assertions`() {
        val claims = extractClaimFingerprints("The answer is 42")
        assertTrue(claims.any { it.key.startsWith("numeric:") })
    }

    @Test
    fun `detectContradictions finds version change`() {
        val tracker = SessionRequestTracker()
        tracker.recordClaims("s1", "Python 3.12.1 is the latest")
        val contradictions = tracker.detectContradictions("s1", "Python 3.15.0 is the latest")
        assertTrue(contradictions.isNotEmpty())
        assertTrue(contradictions.any { it.previousValue == "3.12.1" && it.newValue == "3.15.0" })
    }

    @Test
    fun `detectContradictions returns empty for consistent claims`() {
        val tracker = SessionRequestTracker()
        tracker.recordClaims("s1", "Python 3.12.1 is great")
        val contradictions = tracker.detectContradictions("s1", "Python 3.12.1 is awesome")
        assertTrue(contradictions.isEmpty())
    }

    @Test
    fun `detectContradictions returns empty for unknown session`() {
        val tracker = SessionRequestTracker()
        val contradictions = tracker.detectContradictions("unknown", "Python 3.12 is great")
        assertTrue(contradictions.isEmpty())
    }

    @Test
    fun `cache poisoning prevention - untrusted claims not recorded`() {
        val tracker = SessionRequestTracker()
        tracker.recordClaims("s1", "Python 3.12.1 is latest", trusted = false)
        // Since claim wasn't trusted, no contradictions detected on next check
        val contradictions = tracker.detectContradictions("s1", "Python 3.15.0 is latest")
        assertTrue(contradictions.isEmpty())
    }

    @Test
    fun `recordToolResponse stores excerpt`() {
        val tracker = SessionRequestTracker()
        tracker.recordToolResponse("s1", "GET /api/users", "user_count: 42")
        val excerpts = tracker.getToolExcerpts("s1")
        assertEquals(1, excerpts.size)
        assertEquals("user_count: 42", excerpts["GET /api/users"])
    }

    @Test
    fun `getToolExcerpts returns empty for unknown session`() {
        val tracker = SessionRequestTracker()
        assertTrue(tracker.getToolExcerpts("unknown").isEmpty())
    }

    @Test
    fun `session-less skip returns empty contradictions`() {
        val tracker = SessionRequestTracker()
        // No session recorded, detect should return empty
        val result = tracker.detectContradictions("new-session", "anything")
        assertTrue(result.isEmpty())
    }
}
