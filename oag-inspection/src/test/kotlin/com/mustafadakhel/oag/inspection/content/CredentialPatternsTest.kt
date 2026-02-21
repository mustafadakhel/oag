package com.mustafadakhel.oag.inspection.content

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CredentialPatternsTest {

    @Test
    fun `detects AWS access key`() {
        val body = "key is AKIAIOSFODNN7EXAMPLE"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("aws_access_key"))
    }

    @Test
    fun `rejects AWS key with lowercase characters`() {
        val body = "key is AKIAiosfodnn7example"
        val result = CredentialPatterns.matches(body)
        assertFalse(result.contains("aws_access_key"))
    }

    @Test
    fun `rejects AWS key that is too short`() {
        val body = "key is AKIAIOSFODN"
        val result = CredentialPatterns.matches(body)
        assertFalse(result.contains("aws_access_key"))
    }

    @Test
    fun `detects GitHub personal access token with ghp prefix`() {
        val token = "ghp_" + "A".repeat(36)
        val body = "Authorization: token $token"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("github_pat"))
    }

    @Test
    fun `detects GitHub server-to-server token with ghs prefix`() {
        val token = "ghs_" + "B".repeat(36)
        val body = "token=$token"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("github_server_to_server"))
    }

    @Test
    fun `rejects GitHub token that is too short`() {
        val token = "ghp_" + "A".repeat(10)
        val body = "Authorization: token $token"
        val result = CredentialPatterns.matches(body)
        assertFalse(result.contains("github_pat"))
    }

    @Test
    fun `detects GitHub OAuth token with gho prefix`() {
        val token = "gho_" + "C".repeat(40)
        val body = "oauth_token=$token"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("github_oauth"))
    }

    @Test
    fun `detects GitHub user-to-server token with ghu prefix`() {
        val token = "ghu_" + "D".repeat(36)
        val body = "token=$token"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("github_user_to_server"))
    }

    @Test
    fun `detects RSA private key header`() {
        val body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("private_key"))
    }

    @Test
    fun `detects EC private key header`() {
        val body = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE..."
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("private_key"))
    }

    @Test
    fun `detects generic private key header`() {
        val body = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgk..."
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("private_key"))
    }

    @Test
    fun `does not match public key header as private key`() {
        val body = "-----BEGIN PUBLIC KEY-----\nMIIBIjAN..."
        val result = CredentialPatterns.matches(body)
        assertFalse(result.contains("private_key"))
    }

    @Test
    fun `detects JWT token`() {
        val header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        val payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        val signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        val jwt = "$header.$payload.$signature"
        val body = "Authorization: Bearer $jwt"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("jwt"))
    }

    @Test
    fun `rejects eyJ string without two dots`() {
        val body = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        val result = CredentialPatterns.matches(body)
        assertFalse(result.contains("jwt"))
    }

    @Test
    fun `detects generic api_key assignment`() {
        val body = "api_key=abcdef1234567890ABCDEF"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("generic_api_key"))
    }

    @Test
    fun `detects secret_key assignment`() {
        val body = "secret_key = sk_live_abcdefghijklmnop"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("generic_api_key"))
    }

    @Test
    fun `detects access_token assignment`() {
        val body = "access_token:abcdefghijklmnopqrstuvwx"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("generic_api_key"))
    }

    @Test
    fun `generic api key is case insensitive`() {
        val body = "API_KEY=abcdef1234567890ABCDEF"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("generic_api_key"))
    }

    @Test
    fun `rejects generic api_key with value too short`() {
        val body = "api_key=short"
        val result = CredentialPatterns.matches(body)
        assertFalse(result.contains("generic_api_key"))
    }

    @Test
    fun `detects Slack bot token`() {
        val body = "token=xoxb-123456789012-1234567890123-abcdefghij"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("slack_token"))
    }

    @Test
    fun `detects Slack user token`() {
        val body = "token=xoxp-123456789012-1234567890123-abcdefghij"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("slack_token"))
    }

    @Test
    fun `normal text does not match any credential pattern`() {
        val body = "Hello, this is a normal message with no secrets at all."
        val result = CredentialPatterns.matches(body)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `common english words do not trigger false positives`() {
        val body = "The application key concept is important for understanding the architecture."
        val result = CredentialPatterns.matches(body)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `detects multiple credential types in same body`() {
        val awsKey = "AKIAIOSFODNN7EXAMPLE"
        val ghToken = "ghp_" + "X".repeat(36)
        val body = "aws=$awsKey and github=$ghToken"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("aws_access_key"))
        assertTrue(result.contains("github_pat"))
        assertEquals(2, result.size)
    }

    @Test
    fun `detects three credential types in same body`() {
        val awsKey = "AKIAIOSFODNN7EXAMPLE"
        val slackToken = "xoxb-123456789012-1234567890123-abcdefghij"
        val body = "-----BEGIN RSA PRIVATE KEY-----\naws=$awsKey\nslack=$slackToken"
        val result = CredentialPatterns.matches(body)
        assertTrue(result.contains("aws_access_key"))
        assertTrue(result.contains("private_key"))
        assertTrue(result.contains("slack_token"))
        assertEquals(3, result.size)
    }

    @Test
    fun `ALL list contains entries from every category`() {
        val allNames = CredentialPatterns.ALL.map { it.name }.toSet()
        assertTrue(allNames.contains("aws_access_key"))
        assertTrue(allNames.contains("github_pat"))
        assertTrue(allNames.contains("github_server_to_server"))
        assertTrue(allNames.contains("private_key"))
        assertTrue(allNames.contains("jwt"))
        assertTrue(allNames.contains("generic_api_key"))
        assertTrue(allNames.contains("slack_token"))
    }
}
