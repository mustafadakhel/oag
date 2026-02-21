package com.mustafadakhel.oag.policy.lifecycle

import com.mustafadakhel.oag.policy.core.PolicyAgentProfile
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyMatch
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.SecretScope
import com.mustafadakhel.oag.policy.distribution.PolicyBundleInfo
import com.mustafadakhel.oag.policy.distribution.loadAndValidatePolicySource
import com.mustafadakhel.oag.policy.distribution.loadEd25519PublicKey
import com.mustafadakhel.oag.clearRegexCache
import com.mustafadakhel.oag.policy.evaluation.evaluatePolicy
import com.mustafadakhel.oag.policy.evaluation.evaluatePolicyWithRule
import com.mustafadakhel.oag.policy.evaluation.hashPolicy
import com.mustafadakhel.oag.policy.evaluation.scopeMatchesRequest
import com.mustafadakhel.oag.RateLimitConfig
import com.mustafadakhel.oag.policy.evaluation.normalize

import java.nio.file.Path
import java.time.Instant

data class PolicyVersion(
    val hash: String,
    val timestamp: String
)

class PolicyService(
    private val policyPath: Path,
    policyPublicKeyPath: String? = null,
    private val requireSignature: Boolean = false,
    private val maxHistorySize: Int = DEFAULT_HISTORY_SIZE,
    private val onRegexError: (String) -> Unit = {}
) {
    private data class PolicySnapshot(
        val policy: PolicyDocument,
        val hash: String,
        val bundleInfo: PolicyBundleInfo?,
        val loadedAt: String = java.time.Instant.now().toString()
    )

    private val publicKey = policyPublicKeyPath?.let { loadEd25519PublicKey(Path.of(it)) }

    private fun loadSnapshot(): PolicySnapshot {
        require(!requireSignature || publicKey != null) {
            "policy public key is required when signatures are enforced"
        }
        val source = loadAndValidatePolicySource(policyPath, publicKey, requireSignature)
        val loaded = source.policy.normalize()
        val hash = hashPolicy(loaded)
        val bundleInfo = source.bundleInfo?.let { info ->
            require(info.policyHash == hash) { "policy bundle hash does not match policy content" }
            info
        }
        return PolicySnapshot(policy = loaded, hash = hash, bundleInfo = bundleInfo)
    }

    @Volatile
    private var snapshot: PolicySnapshot = loadSnapshot()

    private val _history = ArrayDeque<PolicyVersion>().apply {
        add(PolicyVersion(snapshot.hash, Instant.now().toString()))
    }

    data class ReloadResult(
        val policy: PolicyDocument,
        val previousHash: String,
        val newHash: String,
        val changed: Boolean
    )

    @Synchronized
    fun reload(): ReloadResult {
        val previousHash = snapshot.hash
        val updated = loadSnapshot()
        snapshot = updated
        clearRegexCache()
        val changed = previousHash != updated.hash
        if (changed) {
            _history.addLast(PolicyVersion(updated.hash, Instant.now().toString()))
            if (_history.size > maxHistorySize) {
                _history.removeFirst()
            }
        }
        return ReloadResult(
            policy = updated.policy,
            previousHash = previousHash,
            newHash = updated.hash,
            changed = changed
        )
    }

    val policyHistory: List<PolicyVersion>
        @Synchronized get() = _history.toList()

    val current: PolicyDocument get() = snapshot.policy

    val currentHash: String get() = snapshot.hash

    val currentBundleInfo: PolicyBundleInfo? get() = snapshot.bundleInfo

    val currentLoadedAt: String get() = snapshot.loadedAt

    fun evaluate(request: PolicyRequest): PolicyDecision =
        evaluatePolicy(snapshot.policy, request)

    fun evaluateWithRule(request: PolicyRequest): PolicyMatch =
        evaluatePolicyWithRule(snapshot.policy, request, onRegexError = onRegexError)

    fun evaluateWithRule(request: PolicyRequest, agentProfile: PolicyAgentProfile?): PolicyMatch =
        evaluatePolicyWithRule(snapshot.policy, request, agentProfile, onRegexError = onRegexError)

    fun resolveAgentProfile(agentId: String?): PolicyAgentProfile? =
        agentId?.let { id -> snapshot.policy.agentProfiles?.find { it.id == id } }

    fun allowedSecrets(request: PolicyRequest, ruleSecrets: List<String>?): Set<String> {
        val base = ruleSecrets.orEmpty().mapNotNull { it.trim().ifEmpty { null } }.toSet()
        val scopes = snapshot.policy.secretScopes ?: return base
        if (base.isEmpty()) return emptySet()
        val scopeIds = scopes.filter { scopeMatches(it, request) }
            .mapNotNull { it.id?.trim() }
            .filter { it.isNotEmpty() }
            .toSet()
        return base.intersect(scopeIds)
    }

    private fun scopeMatches(scope: SecretScope, request: PolicyRequest): Boolean =
        scopeMatchesRequest(scope.hosts, scope.methods, scope.paths, scope.ipRanges, request)

    fun rateLimitConfigs(): List<RateLimitConfig> =
        (snapshot.policy.allow.orEmpty() + snapshot.policy.deny.orEmpty())
            .mapNotNull { rule ->
                val id = rule.id ?: return@mapNotNull null
                val rl = rule.rateLimit ?: return@mapNotNull null
                RateLimitConfig(id, rl.requestsPerSecond ?: DEFAULT_REQUESTS_PER_SECOND, rl.burst ?: DEFAULT_BURST)
            }

    companion object {
        private const val DEFAULT_REQUESTS_PER_SECOND = 10.0
        private const val DEFAULT_BURST = 1
        const val DEFAULT_HISTORY_SIZE = 50
    }
}

