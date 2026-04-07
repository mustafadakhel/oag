package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.FindingSeverity
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.measureTime

class CodeSecurityRulesTest {

    @Test
    fun `sql_fstring matches Python f-string SELECT`() {
        assertTrue(ruleMatches("sql_fstring", """f"SELECT * FROM users WHERE id={user_id}" """))
    }

    @Test
    fun `sql_fstring matches INSERT`() {
        assertTrue(ruleMatches("sql_fstring", """f"INSERT INTO users VALUES({name})" """))
    }

    @Test
    fun `sql_fstring does not match parameterized query`() {
        assertFalse(ruleMatches("sql_fstring", """"SELECT * FROM users WHERE id=?" """))
    }

    @Test
    fun `sql_concat_execute matches string concat in execute`() {
        assertTrue(ruleMatches("sql_concat_execute", """cursor.execute("SELECT * FROM " + table)"""))
    }

    @Test
    fun `sql_concat_execute does not match parameterized execute`() {
        assertFalse(ruleMatches("sql_concat_execute", """cursor.execute(query, params)"""))
    }

    @Test
    fun `cmd_shell_true matches subprocess run with shell=True`() {
        assertTrue(ruleMatches("cmd_shell_true", """subprocess.run(cmd, shell=True)"""))
    }

    @Test
    fun `cmd_shell_true matches subprocess Popen with shell=True`() {
        assertTrue(ruleMatches("cmd_shell_true", """subprocess.Popen(cmd, shell=True)"""))
    }

    @Test
    fun `cmd_shell_true does not match subprocess without shell`() {
        assertFalse(ruleMatches("cmd_shell_true", """subprocess.run(cmd)"""))
    }

    @Test
    fun `cmd_os_system matches os system call`() {
        assertTrue(ruleMatches("cmd_os_system", """os.system("ls -la")"""))
    }

    @Test
    fun `cmd_os_system does not match os listdir`() {
        assertFalse(ruleMatches("cmd_os_system", """os.listdir(".")"""))
    }

    @Test
    fun `cmd_eval_exec matches eval call`() {
        assertTrue(ruleMatches("cmd_eval_exec", """eval(user_input)"""))
    }

    @Test
    fun `cmd_eval_exec matches exec call`() {
        assertTrue(ruleMatches("cmd_eval_exec", """exec(code)"""))
    }

    @Test
    fun `cmd_eval_exec does not match evaluation variable`() {
        assertFalse(ruleMatches("cmd_eval_exec", """evaluation = 5"""))
    }

    @Test
    fun `deser_pickle matches pickle loads`() {
        assertTrue(ruleMatches("deser_pickle", """pickle.loads(data)"""))
    }

    @Test
    fun `deser_pickle matches pickle load`() {
        assertTrue(ruleMatches("deser_pickle", """pickle.load(file)"""))
    }

    @Test
    fun `deser_pickle does not match json loads`() {
        assertFalse(ruleMatches("deser_pickle", """json.loads(data)"""))
    }

    @Test
    fun `deser_yaml_unsafe matches yaml load`() {
        assertTrue(ruleMatches("deser_yaml_unsafe", """yaml.load(data)"""))
    }

    @Test
    fun `deser_yaml_unsafe matches yaml load with SafeLoader on same line`() {
        // The regex itself matches -- suppression is done in the detector
        assertTrue(ruleMatches("deser_yaml_unsafe", """yaml.load(data, Loader=SafeLoader)"""))
    }

    @Test
    fun `crypto_md5 matches hashlib md5`() {
        assertTrue(ruleMatches("crypto_md5", """hashlib.md5(password.encode())"""))
    }

    @Test
    fun `crypto_md5 matches createHash with md5`() {
        assertTrue(ruleMatches("crypto_md5", """crypto.createHash('md5').update(data).digest('hex')"""))
    }

    @Test
    fun `crypto_md5 matches MD5 new`() {
        assertTrue(ruleMatches("crypto_md5", """MD5.new(data)"""))
    }

    @Test
    fun `crypto_md5 does not match hashlib sha256`() {
        assertFalse(ruleMatches("crypto_md5", """hashlib.sha256(data)"""))
    }

    @Test
    fun `secret_assignment matches hardcoded password`() {
        assertTrue(ruleMatches("secret_assignment", """password = "SuperSecret123" """))
    }

    @Test
    fun `secret_assignment matches api_key assignment`() {
        assertTrue(ruleMatches("secret_assignment", """api_key = "abcdefgh12345678" """))
    }

    @Test
    fun `secret_assignment does not match env var lookup`() {
        assertFalse(ruleMatches("secret_assignment", """password = os.environ["DB_PASS"]"""))
    }

    @Test
    fun `secret_assignment does not match short value`() {
        assertFalse(ruleMatches("secret_assignment", """password = "short" """))
    }

    @Test
    fun `secret_assignment does not match value exceeding 128 chars`() {
        val longSecret = "a".repeat(129)
        assertFalse(ruleMatches("secret_assignment", """password = "$longSecret" """))
    }

    @Test
    fun `all high-severity rules are HIGH`() {
        val highIds = setOf(
            "sql_fstring", "sql_concat_execute", "cmd_shell_true",
            "cmd_os_system", "cmd_eval_exec", "deser_pickle",
            "deser_yaml_unsafe", "secret_assignment"
        )
        CodeSecurityRules.ALL
            .filter { it.id in highIds }
            .forEach { rule ->
                assertTrue(
                    rule.severity == FindingSeverity.HIGH,
                    "${rule.id} should be HIGH"
                )
            }
    }

    @Test
    fun `crypto_md5 is MEDIUM severity`() {
        val rule = CodeSecurityRules.ALL.first { it.id == "crypto_md5" }
        assertTrue(rule.severity == FindingSeverity.MEDIUM)
    }

    @Test
    fun `all rules complete against adversarial input within 5ms`() {
        val adversarial = "a".repeat(10_000)
        CodeSecurityRules.ALL.forEach { rule ->
            val elapsed = measureTime { rule.regex.containsMatchIn(adversarial) }
            assertTrue(
                elapsed.inWholeMilliseconds < 5,
                "${rule.id} took ${elapsed.inWholeMilliseconds}ms on adversarial input"
            )
        }
    }

    @Test
    fun `ALL contains exactly 9 rules`() {
        assertTrue(CodeSecurityRules.ALL.size == 9)
    }

    @Test
    fun `all rule IDs are unique`() {
        val ids = CodeSecurityRules.ALL.map { it.id }
        assertTrue(ids.size == ids.toSet().size)
    }

    private fun ruleMatches(id: String, input: String): Boolean {
        val rule = CodeSecurityRules.ALL.first { it.id == id }
        return rule.regex.containsMatchIn(input)
    }
}
