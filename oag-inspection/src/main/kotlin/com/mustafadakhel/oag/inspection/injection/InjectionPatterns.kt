package com.mustafadakhel.oag.inspection.injection

import com.mustafadakhel.oag.inspection.PatternEntry
import com.mustafadakhel.oag.inspection.matchingNames

object InjectionPatterns {

    val DELIMITER_INJECTION: List<PatternEntry> = listOf(
        PatternEntry("chatml_start", Regex("""<\|im_start\|>""", RegexOption.IGNORE_CASE)),
        PatternEntry("chatml_end", Regex("""<\|im_end\|>""", RegexOption.IGNORE_CASE)),
        PatternEntry("inst_tag", Regex("""\[/?INST\]""", RegexOption.IGNORE_CASE)),
        PatternEntry("system_tag", Regex("""</?system>""", RegexOption.IGNORE_CASE)),
        PatternEntry("system_bracket", Regex("""\[SYSTEM\]""", RegexOption.IGNORE_CASE)),
        PatternEntry("alpaca_human", Regex("""###\s*Human:""", RegexOption.IGNORE_CASE)),
        PatternEntry("alpaca_assistant", Regex("""###\s*Assistant:""", RegexOption.IGNORE_CASE)),
        PatternEntry("endoftext", Regex("""<\|endoftext\|>""", RegexOption.IGNORE_CASE)),
        PatternEntry("llama_header", Regex("""<\|start_header_id\|>""", RegexOption.IGNORE_CASE)),
        PatternEntry("llama_eot", Regex("""<\|eot_id\|>""", RegexOption.IGNORE_CASE)),
    )

    val INSTRUCTION_OVERRIDE: List<PatternEntry> = listOf(
        PatternEntry("ignore_instructions", Regex("""ignore\s+(all\s+)?previous\s+instructions?""", RegexOption.IGNORE_CASE)),
        PatternEntry("disregard_instructions", Regex("""disregard\s+(your\s+|all\s+)?(previous\s+)?instructions?""", RegexOption.IGNORE_CASE)),
        PatternEntry("system_override", Regex("""system\s+override""", RegexOption.IGNORE_CASE)),
        PatternEntry("developer_mode", Regex("""developer\s+mode\s+(enabled|on|activated)""", RegexOption.IGNORE_CASE)),
        PatternEntry("new_instructions", Regex("""new\s+instructions?:""", RegexOption.IGNORE_CASE)),
        PatternEntry("forget_instructions", Regex("""forget\s+(all\s+)?(your\s+)?(previous\s+)?instructions?""", RegexOption.IGNORE_CASE)),
        PatternEntry("override_safety", Regex("""override\s+(safety|security)\s+(filters?|guardrails?|checks?)""", RegexOption.IGNORE_CASE)),
        PatternEntry("above_is_false", Regex("""(everything|all)\s+(above|before)\s+(is|was)\s+(false|fake|wrong|a\s+lie)""", RegexOption.IGNORE_CASE)),
        PatternEntry("real_instructions", Regex("""(your\s+)?real\s+instructions?\s+(are|is|follow)""", RegexOption.IGNORE_CASE)),
    )

    val ROLE_ASSUMPTION: List<PatternEntry> = listOf(
        PatternEntry("you_are_now", Regex("""you\s+are\s+now\s+(a|an|the|my)\s""", RegexOption.IGNORE_CASE)),
        PatternEntry("act_as", Regex("""act\s+as\s+(a|an|if\s+you)\s""", RegexOption.IGNORE_CASE)),
        PatternEntry("pretend_to_be", Regex("""pretend\s+(to\s+be|you\s+are)\s""", RegexOption.IGNORE_CASE)),
        PatternEntry("roleplay_as", Regex("""(roleplay|role-play)\s+as\s""", RegexOption.IGNORE_CASE)),
        PatternEntry("simulate_being", Regex("""simulate\s+(being|a)\s""", RegexOption.IGNORE_CASE)),
        PatternEntry("switch_to_role", Regex("""switch\s+to\s+(the\s+)?role\s+of\s""", RegexOption.IGNORE_CASE)),
    )

    val PROMPT_LEAKING: List<PatternEntry> = listOf(
        PatternEntry("reveal_system_prompt", Regex("""(reveal|show|display|output|print|repeat)\s+(your\s+)?(system\s+prompt|initial\s+prompt|instructions?)""", RegexOption.IGNORE_CASE)),
        PatternEntry("what_is_your_prompt", Regex("""what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions?)""", RegexOption.IGNORE_CASE)),
        PatternEntry("beginning_of_conversation", Regex("""(beginning|start)\s+of\s+(this\s+|the\s+)?conversation""", RegexOption.IGNORE_CASE)),
        PatternEntry("repeat_above", Regex("""repeat\s+(everything|the\s+text|all)\s+(above|before\s+this)""", RegexOption.IGNORE_CASE)),
        PatternEntry("leak_context_window", Regex("""(dump|leak|exfiltrate)\s+(your\s+)?(context|memory|training\s+data)""", RegexOption.IGNORE_CASE)),
        PatternEntry("verbatim_instructions", Regex("""(verbatim|exact|word\s+for\s+word)\s+(copy|text)\s+of\s+(your\s+)?(instructions?|prompt)""", RegexOption.IGNORE_CASE)),
    )

    val JAILBREAK: List<PatternEntry> = listOf(
        PatternEntry("do_anything_now", Regex("""do\s+anything\s+now""", RegexOption.IGNORE_CASE)),
        PatternEntry("no_restrictions", Regex("""(you\s+have\s+)?no\s+(restrictions?|limitations?|rules?|constraints?)""", RegexOption.IGNORE_CASE)),
        PatternEntry("jailbreak", Regex("""jail\s*break""", RegexOption.IGNORE_CASE)),
        PatternEntry("unrestricted_mode", Regex("""unrestricted\s+mode""", RegexOption.IGNORE_CASE)),
        PatternEntry("bypass_filters", Regex("""bypass\s+(your\s+)?(safety\s+)?(filters?|guardrails?)""", RegexOption.IGNORE_CASE)),
        PatternEntry("hypothetical_scenario", Regex("""(hypothetical|fictional)\s+scenario\s+where\s+""", RegexOption.IGNORE_CASE)),
        PatternEntry("opposite_day", Regex("""opposite\s+day""", RegexOption.IGNORE_CASE)),
        PatternEntry("evil_twin", Regex("""(evil|dark|shadow)\s+(twin|version|mode|alter\s*ego)""", RegexOption.IGNORE_CASE)),
        PatternEntry("god_mode", Regex("""god\s+mode""", RegexOption.IGNORE_CASE)),
        PatternEntry("sudo_mode", Regex("""sudo\s+mode""", RegexOption.IGNORE_CASE)),
    )

    val ENCODING_MARKERS: List<PatternEntry> = listOf(
        PatternEntry("base64_decode_directive", Regex("""(base64|b64)\s*(decode|decrypt|interpret)""", RegexOption.IGNORE_CASE)),
        PatternEntry("rot13_directive", Regex("""rot13\s*(decode|decrypt|interpret|translate)""", RegexOption.IGNORE_CASE)),
        PatternEntry("hex_decode_directive", Regex("""(hex|hexadecimal)\s*(decode|decrypt|interpret|convert)""", RegexOption.IGNORE_CASE)),
        PatternEntry("unicode_escape_directive", Regex("""(unicode|utf-?8)\s*(decode|escape|interpret)""", RegexOption.IGNORE_CASE)),
    )

    val ALL: List<PatternEntry> = DELIMITER_INJECTION + INSTRUCTION_OVERRIDE +
        ROLE_ASSUMPTION + PROMPT_LEAKING + JAILBREAK + ENCODING_MARKERS

    fun matches(content: String): List<String> = ALL.matchingNames(content)
}
