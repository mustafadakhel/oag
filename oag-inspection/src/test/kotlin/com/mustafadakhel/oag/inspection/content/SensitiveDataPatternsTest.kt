package com.mustafadakhel.oag.inspection.content

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SensitiveDataPatternsTest {

    @Test
    fun `detects Visa credit card number`() {
        val body = "card: 4111111111111111"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("credit_card_visa"))
    }

    @Test
    fun `detects Visa credit card with 13 digits`() {
        val body = "card: 4111111111111"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("credit_card_visa"))
    }

    @Test
    fun `detects Mastercard credit card number`() {
        val body = "card: 5105105105105100"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("credit_card_mastercard"))
    }

    @Test
    fun `detects Amex credit card number`() {
        val body = "card: 371449635398431"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("credit_card_amex"))
    }

    @Test
    fun `detects Amex card starting with 34`() {
        val body = "amex: 340000000000009"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("credit_card_amex"))
    }

    @Test
    fun `detects SSN in xxx-xx-xxxx format`() {
        val body = "ssn: 123-45-6789"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("ssn"))
    }

    @Test
    fun `does not detect SSN without dashes`() {
        val body = "number: 123456789"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertFalse(result.contains("ssn"))
    }

    @Test
    fun `detects IBAN number`() {
        val body = "iban: GB29NWBK60161331926819"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("iban"))
    }

    @Test
    fun `detects German IBAN`() {
        val body = "payment to DE89370400440532013000"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("iban"))
    }

    @Test
    fun `detects email address`() {
        val body = "contact: user@example.com"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("email"))
    }

    @Test
    fun `detects email with subdomain`() {
        val body = "send to admin@mail.corp.example.co.uk"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("email"))
    }

    @Test
    fun `detects US phone number`() {
        val body = "call: 555-123-4567"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("us_phone"))
    }

    @Test
    fun `detects US phone with country code`() {
        val body = "phone: +1-555-123-4567"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("us_phone"))
    }

    @Test
    fun `detects US phone with parentheses`() {
        val body = "phone: (555) 123-4567"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("us_phone"))
    }

    @Test
    fun `category filter returns only financial patterns`() {
        val body = "card: 4111111111111111 ssn: 123-45-6789 email: user@example.com phone: 555-123-4567"
        val result = SensitiveDataPatterns.matchesByCategory(body, listOf("financial")).values.flatten()
        assertTrue(result.contains("credit_card_visa"))
        assertFalse(result.contains("ssn")) // SSN is pii, not financial
        assertFalse(result.contains("email"))
        assertFalse(result.contains("us_phone"))
    }

    @Test
    fun `category filter returns only pii patterns`() {
        val body = "card: 4111111111111111 email: user@example.com phone: 555-123-4567"
        val result = SensitiveDataPatterns.matchesByCategory(body, listOf("pii")).values.flatten()
        assertFalse(result.contains("credit_card_visa"))
        assertTrue(result.contains("email"))
        assertTrue(result.contains("us_phone"))
    }

    @Test
    fun `category filter returns only credentials patterns`() {
        val body = "AKIAIOSFODNN7EXAMPLE email: user@example.com card: 4111111111111111"
        val result = SensitiveDataPatterns.matchesByCategory(body, listOf("credentials")).values.flatten()
        assertTrue(result.contains("aws_access_key"))
        assertFalse(result.contains("email"))
        assertFalse(result.contains("credit_card_visa"))
    }

    @Test
    fun `null categories returns matches from all categories`() {
        val body = "card: 4111111111111111 email: user@example.com"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("credit_card_visa"))
        assertTrue(result.contains("email"))
    }

    @Test
    fun `empty categories list returns matches from all categories`() {
        val body = "card: 4111111111111111 email: user@example.com"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.contains("credit_card_visa"))
        assertTrue(result.contains("email"))
    }

    @Test
    fun `matchesByCategory groups results correctly`() {
        val body = "card: 4111111111111111 ssn: 123-45-6789 email: user@example.com"
        val result = SensitiveDataPatterns.matchesByCategory(body)
        assertTrue(result.containsKey("financial"))
        assertTrue(result.containsKey("pii"))
        assertTrue(result["financial"]!!.contains("credit_card_visa"))
        assertTrue(result["pii"]!!.contains("ssn")) // SSN is pii
        assertTrue(result["pii"]!!.contains("email"))
    }

    @Test
    fun `matchesByCategory with category filter limits output`() {
        val body = "card: 4111111111111111 email: user@example.com"
        val result = SensitiveDataPatterns.matchesByCategory(body, listOf("financial"))
        assertTrue(result.containsKey("financial"))
        assertFalse(result.containsKey("pii"))
    }

    @Test
    fun `matchesByCategory returns empty map for no matches`() {
        val body = "just a normal sentence with nothing sensitive"
        val result = SensitiveDataPatterns.matchesByCategory(body)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `normal text does not match any sensitive data pattern`() {
        val body = "Hello, this is a perfectly normal message about the weather."
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.isEmpty())
    }

    @Test
    fun `numeric text that is not a card number does not match`() {
        val body = "order 12345 has 3 items"
        val result = SensitiveDataPatterns.matchesByCategory(body).values.flatten()
        assertTrue(result.isEmpty())
    }

    @Test
    fun `ALL list contains entries from every category`() {
        val byCategory = SensitiveDataPatterns.matchesByCategory(
            "card: 4111111111111111 AKIAIOSFODNN7EXAMPLE ssn: 123-45-6789"
        )
        assertTrue(byCategory.containsKey("financial"))
        assertTrue(byCategory.containsKey("credentials"))
        assertTrue(byCategory.containsKey("pii"))
    }

    @Test
    fun `multiple financial detections in one body`() {
        val body = "visa: 4111111111111111 mc: 5105105105105100 amex: 371449635398431"
        val result = SensitiveDataPatterns.matchesByCategory(body, listOf("financial")).values.flatten()
        assertTrue(result.contains("credit_card_visa"))
        assertTrue(result.contains("credit_card_mastercard"))
        assertTrue(result.contains("credit_card_amex"))
        assertEquals(3, result.size)
    }

    @Test
    fun `matchesByCategory with multiple categories`() {
        val body = "card: 4111111111111111 email: user@example.com AKIAIOSFODNN7EXAMPLE"
        val result = SensitiveDataPatterns.matchesByCategory(body, listOf("financial", "credentials"))
        assertTrue(result.containsKey("financial"))
        assertTrue(result.containsKey("credentials"))
        assertFalse(result.containsKey("pii"))
    }
}
