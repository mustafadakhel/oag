package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.label
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CodeBlockExtractorTest {

    @Test
    fun `extracts markdown fence with language tag`() {
        val text = "```python\nprint('hello')\n```"
        val blocks = CodeBlockExtractor.extract(text)

        assertEquals(1, blocks.size)
        assertEquals("print('hello')\n", blocks[0].code)
        assertEquals("python", blocks[0].language)
        assertEquals(CodeBlockSource.MARKDOWN_FENCE, blocks[0].source)
    }

    @Test
    fun `extracts markdown fence without language tag`() {
        val text = "```\nsome code\n```"
        val blocks = CodeBlockExtractor.extract(text)

        assertEquals(1, blocks.size)
        assertNull(blocks[0].language)
    }

    @Test
    fun `extracts multiple markdown fences`() {
        val text = "```python\nfoo()\n```\ntext\n```javascript\nbar()\n```"
        val blocks = CodeBlockExtractor.extract(text)

        assertEquals(2, blocks.size)
        assertEquals("python", blocks[0].language)
        assertEquals("javascript", blocks[1].language)
    }

    @Test
    fun `extracts JSON tool_call code field`() {
        val text = """{"code": "print('hello')"}"""
        val blocks = CodeBlockExtractor.extract(text)

        assertEquals(1, blocks.size)
        assertEquals("print('hello')", blocks[0].code)
        assertEquals(CodeBlockSource.JSON_TOOL_CALL, blocks[0].source)
        assertNull(blocks[0].language)
    }

    @Test
    fun `unescapes JSON code field`() {
        val text = """{"code": "line1\nline2\t\"quoted\"\\slash"}"""
        val blocks = CodeBlockExtractor.extract(text)

        assertEquals(1, blocks.size)
        assertEquals("line1\nline2\t\"quoted\"\\slash", blocks[0].code)
    }

    @Test
    fun `normalizes language aliases`() {
        val cases = mapOf(
            "py" to "python",
            "js" to "javascript",
            "ts" to "typescript",
            "sh" to "bash",
            "shell" to "bash",
            "rb" to "ruby",
            "yml" to "yaml"
        )
        cases.forEach { (alias, expected) ->
            val text = "```$alias\ncode\n```"
            val blocks = CodeBlockExtractor.extract(text)
            assertEquals(expected, blocks[0].language, "Expected $alias -> $expected")
        }
    }

    @Test
    fun `unknown language passes through`() {
        val text = "```rust\nfn main() {}\n```"
        val blocks = CodeBlockExtractor.extract(text)

        assertEquals("rust", blocks[0].language)
    }

    @Test
    fun `returns empty for plain text with no code blocks`() {
        val blocks = CodeBlockExtractor.extract("Just a regular response with no code.")
        assertTrue(blocks.isEmpty())
    }

    @Test
    fun `returns empty for body exceeding size limit`() {
        val text = "```python\n${"a".repeat(524_289)}\n```"
        val blocks = CodeBlockExtractor.extract(text)
        assertTrue(blocks.isEmpty())
    }

    @Test
    fun `empty code block produces empty code string`() {
        val text = "```python\n\n```"
        val blocks = CodeBlockExtractor.extract(text)

        assertEquals(1, blocks.size)
        assertEquals("\n", blocks[0].code)
    }

    @Test
    fun `CodeBlockSource label returns lowercase name`() {
        assertEquals("markdown_fence", CodeBlockSource.MARKDOWN_FENCE.label())
        assertEquals("json_tool_call", CodeBlockSource.JSON_TOOL_CALL.label())
    }
}
