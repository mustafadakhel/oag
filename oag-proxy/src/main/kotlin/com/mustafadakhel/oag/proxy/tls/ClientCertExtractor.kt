package com.mustafadakhel.oag.proxy.tls

import com.mustafadakhel.oag.AuthnMethod
import com.mustafadakhel.oag.CertInfo
import com.mustafadakhel.oag.IdentityResult

import java.security.cert.X509Certificate
import javax.naming.ldap.LdapName
import javax.security.auth.x500.X500Principal

private const val SAN_TYPE_DNS = 2

internal fun extractAgentId(cert: X509Certificate): String? =
    extractSanDns(cert) ?: extractCn(cert)

internal fun extractCn(cert: X509Certificate): String? {
    val dn = cert.subjectX500Principal.getName(X500Principal.RFC2253)
    return parseCn(dn)
}

internal fun extractSanDns(cert: X509Certificate): String? {
    val sans = runCatching { cert.subjectAlternativeNames }.getOrNull() ?: return null
    return sans.firstOrNull { it.size >= 2 && (it[0] as? Int) == SAN_TYPE_DNS }
        ?.get(1) as? String
}

private fun parseCn(dn: String): String? =
    runCatching { LdapName(dn) }.getOrNull()
        ?.rdns
        ?.firstOrNull { it.type.equals("CN", ignoreCase = true) }
        ?.value
        ?.toString()

internal fun extractCertificateIdentity(cert: X509Certificate): IdentityResult {
    val agentId = extractAgentId(cert)
    return IdentityResult(
        actorId = agentId,
        authnMethod = AuthnMethod.CERTIFICATE,
        certInfo = CertInfo(
            subject = cert.subjectX500Principal.getName(X500Principal.RFC2253),
            issuer = cert.issuerX500Principal.getName(X500Principal.RFC2253),
            serialNumber = cert.serialNumber.toString()
        )
    )
}
