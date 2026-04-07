package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.inspection.EvidenceKey
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.ResponseTextBody
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CodeSecurityDetectorTest {

    private val detector = CodeSecurityDetector()
    private val ctx = InspectionContext()

    @Test
    fun `detects SQL injection in python f-string`() {
        val input = response("```python\nquery = f\"SELECT * FROM users WHERE id={user_id}\"\n```")
        val findings = detector.inspect(input, ctx)

        assertTrue(findings.isNotEmpty())
        assertEquals(FindingType.CODE_VULNERABILITY, findings[0].type)
    }

    @Test
    fun `finding evidence contains pattern and cwe`() {
        val input = response("```python\nos.system(\"rm -rf /\")\n```")
        val findings = detector.inspect(input, ctx)

        assertTrue(findings.isNotEmpty())
        assertEquals("cmd_os_system", findings[0].evidence[EvidenceKey.PATTERN])
        assertEquals("CWE-78", findings[0].evidence[EvidenceKey.CWE])
    }

    @Test
    fun `finding evidence contains code_block_source`() {
        val input = response("```python\neval(user_input)\n```")
        val findings = detector.inspect(input, ctx)

        assertEquals("markdown_fence", findings[0].evidence[EvidenceKey.CODE_BLOCK_SOURCE])
    }

    @Test
    fun `finding evidence contains language when present`() {
        val input = response("```python\neval(user_input)\n```")
        val findings = detector.inspect(input, ctx)

        assertEquals("python", findings[0].evidence[EvidenceKey.LANGUAGE])
    }

    @Test
    fun `finding evidence omits language when absent`() {
        val input = response("```\neval(user_input)\n```")
        val findings = detector.inspect(input, ctx)

        assertFalse(findings[0].evidence.containsKey(EvidenceKey.LANGUAGE))
    }

    @Test
    fun `returns empty for clean code`() {
        val input = response("```python\nresult = cursor.execute(query, params)\nprint(result)\n```")
        val findings = detector.inspect(input, ctx)

        assertTrue(findings.isEmpty())
    }

    @Test
    fun `returns empty for no code blocks`() {
        val input = response("Just a regular response with no code.")
        val findings = detector.inspect(input, ctx)

        assertTrue(findings.isEmpty())
    }

    @Test
    fun `detects multiple vulnerabilities across blocks`() {
        val input = response("```python\nos.system(\"ls\")\n```\nSome text.\n```python\npickle.loads(data)\n```")
        val findings = detector.inspect(input, ctx)

        assertTrue(findings.size >= 2)
        assertTrue(findings.any { it.evidence[EvidenceKey.PATTERN] == "cmd_os_system" })
        assertTrue(findings.any { it.evidence[EvidenceKey.PATTERN] == "deser_pickle" })
    }

    @Test
    fun `time budget prevents hanging`() {
        val timedDetector = CodeSecurityDetector(timeBudgetNanos = 1L)
        val input = response("```python\nos.system(\"ls\")\npickle.loads(data)\neval(x)\n```")
        val findings = timedDetector.inspect(input, ctx)
        assertTrue(findings.size <= CodeSecurityRules.ALL.size)
    }

    @Test
    fun `constructor rejects ReDoS-vulnerable regex`() {
        // (a+)+ on "aaa...!" causes exponential backtracking
        val badRule = CodeSecurityRule(
            id = "bad",
            cwe = "CWE-0",
            regex = Regex("""^(a+)+b"""),
            severity = FindingSeverity.HIGH,
            description = "ReDoS pattern"
        )
        assertFailsWith<IllegalArgumentException> {
            CodeSecurityDetector(
                rules = listOf(badRule),
                timeBudgetNanos = 50_000_000L
            )
        }
    }

    @Test
    fun `all findings use LOG recommended action`() {
        val input = response("```python\nos.system(\"ls\")\neval(x)\npickle.loads(d)\n```")
        val findings = detector.inspect(input, ctx)

        findings.forEach { finding ->
            assertEquals(listOf(RecommendedAction.LOG), finding.recommendedActions)
        }
    }

    @Test
    fun `all findings use default confidence`() {
        val input = response("```python\nos.system(\"ls\")\n```")
        val findings = detector.inspect(input, ctx)

        findings.forEach { finding ->
            assertEquals(0.80, finding.confidence)
        }
    }

    @Test
    fun `all findings have ResponseBody location`() {
        val input = response("```python\nos.system(\"ls\")\n```")
        val findings = detector.inspect(input, ctx)

        findings.forEach { finding ->
            assertEquals(FindingLocation.ResponseBody, finding.location)
        }
    }

    @Test
    fun `yaml load with SafeLoader is suppressed`() {
        val input = response("```python\ndata = yaml.load(content, Loader=SafeLoader)\n```")
        val findings = detector.inspect(input, ctx)

        assertTrue(findings.none { it.evidence[EvidenceKey.PATTERN] == "deser_yaml_unsafe" })
    }

    @Test
    fun `yaml safe_load is not matched by yaml load regex`() {
        val input = response("```python\ndata = yaml.safe_load(content)\n```")
        val findings = detector.inspect(input, ctx)

        assertTrue(findings.none { it.evidence[EvidenceKey.PATTERN] == "deser_yaml_unsafe" })
    }

    @Test
    fun `yaml load without SafeLoader is detected`() {
        val input = response("```python\ndata = yaml.load(content)\n```")
        val findings = detector.inspect(input, ctx)

        assertTrue(findings.any { it.evidence[EvidenceKey.PATTERN] == "deser_yaml_unsafe" })
    }

    @Test
    fun `yaml mixed safe and unsafe in same block produces finding`() {
        val input = response("```python\ndata1 = yaml.load(content, Loader=SafeLoader)\ndata2 = yaml.load(content)\n```")
        val findings = detector.inspect(input, ctx)

        assertTrue(findings.any { it.evidence[EvidenceKey.PATTERN] == "deser_yaml_unsafe" })
    }

    private fun response(text: String) = ResponseTextBody(text, 200, "text/plain")
}
