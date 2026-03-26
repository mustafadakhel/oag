package com.mustafadakhel.oag.inspection.injection

import kotlin.test.Test
import kotlin.test.assertTrue

class DjlHuggingFaceTokenizerTest {

    @Test
    fun `DJL is available on test classpath`() {
        assertTrue(DjlHuggingFaceTokenizer.isAvailable())
    }

    @Test
    fun `createOrNull returns null for non-existent path`() {
        val tokenizer = DjlHuggingFaceTokenizer.createOrNull("/nonexistent/tokenizer.json")
        assertTrue(tokenizer == null)
    }
}
