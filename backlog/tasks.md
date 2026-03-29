> Legend
> [ ] todo  [>] in progress  [x] done
> [-] blocked  [~] in review  [/] paused
> [!] urgent  [?] needs clarification

# E31: Apache 2.0 License Migration

## M1: License Change ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- [x] 1. Add Apache 2.0 headers to all .kt files — Prepend standard 13-line Apache 2.0 license header to 396 .kt files across 10 modules, verify build passes |dep:none
- [x] 2. Replace LICENSE with Apache 2.0 text — Replace entire LICENSE file with canonical Apache License 2.0 from apache.org, no modifications |dep:none
- [x] 3. Create NOTICE file — Create repository root NOTICE with project name and copyright line (2 lines total) |dep:none
- [x] 4. Update CONTRIBUTING.md line 91 — Change "Business Source License 1.1" to "Apache License 2.0" in contribution terms |dep:none
- [x] 5. Update README.md license section — Replace lines 112-118 BSL description with Apache 2.0 one-liner, remove revenue threshold text |dep:none
- [x] 6. Add CHANGELOG.md v0.2.0 entry — Insert v0.2.0 section after line 1 with license change note |dep:none
- [-] 7. Tag release v0.2.0 — Create git tag v0.2.0 pointing to license-change commit |dep:2,3,4,5,6 |!blocked: Waiting for PR merge to main
- [ ] 8. Verify license changes — Run 8-point verification checklist (grep headers, no BSL refs, build passes, license detection) |dep:7

## M2: Protective Measures ~~~~~~~~~~~~~~~~~~~~~~~~

- [ ] 9. File BIS export control notification — Send email to crypt@bis.doc.gov with project info and ECCN 5D002 statement |dep:7
- [ ] 10. Apply for trademark protection — Research existing marks and file USPTO TEAS Plus for "OAG" and "Open Agent Guard" in Class 42 (SaaS) and Class 9 (software) |dep:none

## M3: Community Communication ~~~~~~~~~~~~~~~~~~~~

- [ ] 11. Write GitHub release notes — Customize v0.2.0 release notes to lead with Apache 2.0 transition, emphasize no restrictions on commercial use |dep:7
- [ ] 12. Draft announcement content — Write 500-800 word blog/announcement explaining why relicense, competitive parity, no CLA, same roadmap |dep:7

## Notes for E31

**License Strategy Context:**
- Source: planning/license-strategy/techplan.md (audited plan.md)
- Two commits: (1) headers first, (2) LICENSE file + NOTICE + docs
- Header script exists at: planning/license-strategy/add-headers.sh
- All file paths and line numbers verified against actual codebase 2026-03-28

**Task Grouping:**
- M1 (License Change): 8 tasks, atomic, all required for v0.2.0 release
- M2 (Protective Measures): 2 tasks, independent of M1, post-release recommended
- M3 (Communication): 2 tasks, post-release, timing flexible

**Implementation Notes:**
- Task 1: Script is idempotent; verify no @file: annotations exist before running
- Task 1: Use printf '%s\n' for LF line endings on all platforms (Git Bash on Windows)
- Tasks 2-6: All must be completed before Task 7 (tagging)
- Task 7: Tag should be v0.2.0 (minor version bump, not API-breaking)
- Task 8: Verification includes 8 automated checks + 2 manual post-push checks (license detection, tag correctness)
- Task 9: Optional but recommended after LICENSE file deployed; notification is free
- Task 10: $500-600 cost, 2-3 hours effort, deferrable until adoption justifies brand protection investment
- Task 11: GitHub release workflow auto-generates draft+prerelease; edit to customize and mark non-prerelease
- Task 12: Emphasize competitive parity (all competitors are MIT/Apache 2.0), no CLA friction, patent grant protection

**Estimated Effort:**
- M1: ~1 hour total
- M2: ~3.5 hours total (9 is 15 min, 10 is 2-3 hours)
- M3: ~2.5 hours total (11 is 30 min, 12 is 2 hours)

# E32: Architectural Refactoring ✓

## M1: Dead Code & Safety ✓ ~~~~~~~~~~~~~~

**2 tasks completed.** See git history (tasks 1–2).

## M2: Delete PolicyCapability ✓ ~~~~~~~~~~~~~~

**1 task completed.** See git history (task 3).

## M3: SecretScope Deduplication ✓ ~~~~~~~~~~~~~~

**2 tasks completed.** See git history (tasks 4–5).

## M4: Small Refactors ✓ ~~~~~~~~~~~~~~

**3 tasks completed.** See git history (tasks 6–8).

## M5: Collapse PipelineError ✓ ~~~~~~~~~~~~~~

**1 task completed.** See git history (task 9).

# E33: ML Config & Docker ✓

## M6: ML Config & Docker ✓ ~~~~~~~~~~~~~~

**3 tasks completed.** See git history (tasks 10–12).

# E34: HuggingFace Tokenizer Implementation ✓

## M7: HuggingFace Tokenizer Implementation ✓ ~~~~~~~~~~~~~~

**4 tasks completed.** See git history (tasks 13–16).

# E35: Bug Fixes & Security Hardening ✓

## M8: Bug Fixes & Security Hardening ✓ ~~~~~~~~~~~~~~

**4 tasks completed.** See git history (tasks 17–20).

# E36: Hallucination Detection

## M9: Foundation ✓ ~~~~~~~~~~~~~~

### S1: Enums (oag-core, oag-policy)

- [x] 21a. Add FindingType.HALLUCINATION to enum in Finding.kt |dep:none
- [x] 21b. Add "hallucination" to FindingTypeLabels.valid in ValidLabels.kt |dep:none
- [x] 21c. Add ReasonCode.HALLUCINATION_DETECTED to enum in PolicyDecision.kt (category: SECURITY) — append after RESPONSE_PLUGIN_DETECTED in the SECURITY block |dep:none
- [x] 21d. Add FindingLocation.ResponseBody to sealed interface in FindingConstants.kt |dep:none
- [x] 21e. Add HALLUCINATION_DETECTED to WebhookEventType enum and WebhookPayloadKeys constants |dep:none

### S2: Policy Model (oag-policy)

- [x] 22a. Create PolicyHallucinationCheck @Serializable data class in PolicyInspection.kt — all signal toggles, weights, endpoint config |dep:none
- [x] 22b. Create HallucinationMode and TimeoutAction enums in PolicyInspection.kt |dep:none
- [x] 22c. Add hallucinationCheck field to PolicyDefaults and PolicyRule — position after skipPluginDetection, before findingSuppressions (before topicClassification if E37 merged first) |dep:22a
- [x] 22d. Create HallucinationCheckValidator.kt with validate() function following buildList pattern |dep:22a
- [x] 22e. Wire HallucinationCheckValidator into PolicyValidation.kt and RuleValidator.kt |dep:22c,22d
- [x] 22f. Add hallucination doctor warnings to DoctorCommand — unreachable threshold, session without --session, external endpoint without timeout |dep:22a

### S3: SafeOutboundClient (oag-core)

- [x] 23a. Create SafeOutboundClient class in oag-core — DNS resolution + isSpecialPurposeAddress check, IP literal rejection via isIpLiteralHost |dep:none
- [x] 23b. Add DNS pinning and redirect prevention to SafeOutboundClient — resolve once, connect to resolved IP, HttpClient.Redirect.NEVER |dep:23a
- [x] 23c. Add OutboundResult sealed class — Success/Failure/Blocked variants |dep:23a
- [x] 23d. Write SafeOutboundClient tests — SSRF prevention, timeout, DNS pinning, IP literal rejection |dep:23a,23b,23c

### S4: Request Body Threading (oag-proxy)

- [x] 24a. Add requestBodyText: String? = null to BufferedInspectionContext — after matchedRule, before onError; must default to null to avoid breaking existing call sites |dep:none
- [x] 24b. Add requestBodyText parameter to ResponseRelayer.relay() signature and thread through RelayState |dep:24a
- [x] 24c. Pass context.bufferedBodyText from HttpRelayHandler into ResponseRelayer.relay() |dep:24b

### S5: Audit Models & Wiring (oag-audit)

- [x] 25a. Create AuditHallucinationSignal @Serializable data class in AuditModels.kt |dep:none
- [x] 25b. Add hallucination fields to AuditContentInspection — score, signals, mode, bypassed_streaming, etc. |dep:25a
- [x] 25c. Add hallucination fields to InspectionAccumulator in ResponseInspectionStep.kt |dep:25b
- [x] 25d. Add hallucination fields to ResponseRelayResult in ContentModels.kt |dep:25c
- [x] 25e. Wire hallucination fields through buildFinalContentInspection in RelayAuditHelpers.kt + update isNonTrivial |dep:25b,25d

### S6: Pipeline Shell & Integration (oag-proxy)

- [x] 25f. Create HallucinationCheckStep implementing ResponseInspectionStep — shell that reads config, runs no sub-checks yet, writes empty results to accumulator |dep:21a,21c,22a,24a,25c
- [x] 25g. Wire HallucinationCheckStep into buildInspectionChain and buildInspectionPlan in ResponseRelay.kt |dep:25f
- [x] 25h. Write integration test — enable hallucination_check in policy, verify audit event contains hallucination fields |dep:25g

## M10: Deterministic Signals ~~~~~~~~~~~~~ ✓

### S1: Impossible Claims Matcher

- [x] 26a. Design and create impossible-claims.yaml resource file with ~200 patterns organized by category (versions, models, dates) |dep:none
- [x] 26b. Create ImpossibleClaimMatcher class — loads YAML, compiles patterns via Aho-Corasick for contains + isRegexSafe for anchored patterns |dep:26a
- [x] 26c. Integrate ImpossibleClaimMatcher as sub-check in HallucinationCheckStep |dep:25f,26b
- [x] 26d. Add impossible_claims_path support — user-extensible patterns file validated at load time |dep:26b
- [x] 26e. Write tests — pattern matching, false positive exclusion (hypothetical context), anchored patterns, custom file loading |dep:26c

### S2: URL Verification

- [x] 27a. Create UrlVerifier class using SafeOutboundClient — extract URLs from response text, HEAD request, status code handling (2xx/404/5xx) |dep:23a
- [x] 27b. Add url_verification_allowlist support — skip known-good domains |dep:27a
- [x] 27c. Integrate UrlVerifier as sub-check in HallucinationCheckStep |dep:25f,27a
- [x] 27d. Write tests — URL extraction, NXDOMAIN detection, allowlist skipping, SSRF prevention (private IPs rejected) |dep:27c

### S3: Package Verification

- [x] 28a. Create PackageVerifier class using SafeOutboundClient — extract package names from pip/npm/import patterns, query registry APIs |dep:23a
- [x] 28b. Add bloom filter cache with symmetric TTL for positive/negative results |dep:28a
- [x] 28c. Add package_registry_mirror support for private registries |dep:28a
- [x] 28d. Integrate PackageVerifier as sub-check in HallucinationCheckStep |dep:25f,28a
- [ ] 28e. Write tests — package extraction regex, registry 404 detection, cache behavior, mirror support |dep:28d (phantom — deferred: JDK Host header restriction prevents registry 404 + cache tests)

## M11: Probabilistic & Session Signals ~~~~~~~~~~~~~~ ✓

### S1: Logprob Analysis

- [x] 29a. Create LogprobAnalyzer class — parse logprobs from OpenAI/Anthropic response JSON, compute mean/min logprob, map to [0,1] score |dep:none
- [x] 29b. Integrate LogprobAnalyzer as sub-check in HallucinationCheckStep — skip if logprobs not present in response |dep:25f,29a
- [x] 29c. Write tests — logprob extraction from different provider formats, score mapping, skip behavior when absent |dep:29b

### S2: Claim Contradiction Detection

- [x] 30a. Extend SessionRequestTracker with claim fingerprint cache — regex extraction for URLs, version strings, numeric assertions |dep:none
- [x] 30b. Create ClaimContradictionDetector — compare new claims against cached claims, detect contradictions |dep:30a
- [x] 30c. Add cache poisoning prevention — exclude claims from responses flagged by other signals |dep:30b
- [x] 30d. Integrate as sub-check in HallucinationCheckStep — skip if no session |dep:25f,30b
- [x] 30e. Write tests — claim extraction, contradiction detection, cache poisoning prevention, session-less skip |dep:30d

### S3: Tool Receipt Verification

- [x] 31a. Extend SessionRequestTracker to cache tool response excerpts keyed by request path + method |dep:none
- [x] 31b. Create ToolReceiptVerifier — extract claims from LLM response, compare against cached tool data |dep:31a
- [x] 31c. Integrate as sub-check in HallucinationCheckStep — skip if no session |dep:25f,31b
- [x] 31d. Write tests — tool response caching, claim verification, session-less skip |dep:31c

## M12: External Integration ✓ ~~~~~~~~~~~~~~

### S1: External Verifier & Circuit Breaker

- [x] 32a. Create ExternalVerifier class using SafeOutboundClient — POST response content to endpoint, parse score response |dep:23a,24a
- [x] 32b. Add circuit breaker for external endpoint — auto-disable after N timeouts, emit audit event |dep:32a
- [x] 32c. Add HTTPS enforcement and endpoint SSRF validation at policy load time |dep:22d,32a
- [x] 32d. Integrate as sub-check in HallucinationCheckStep |dep:25f,32a
- [ ] 32e. Write tests — endpoint call, timeout handling, circuit breaker, HTTPS enforcement, SSRF rejection |dep:32d (phantom — deferred: JDK Host header restriction prevents endpoint call + timeout tests)

# E37: Topical Dialog Rails [✓]

## M13: External Classifier ~~~~~~~~~~~~~~

### S1: Policy Model (oag-policy)

- [x] 33a. Create PolicyTopicClassification @Serializable data class in PolicyTopicClassification.kt — fields: enabled, denied_topics, allowed_topics, confidence_threshold, endpoint_url, endpoint_timeout_ms, signing_secret, on_error, max_text_bytes (all nullable, no defaults) |dep:none
- [x] 33b. Add topicClassification: PolicyTopicClassification? field to PolicyRule.kt — position after skipPluginDetection (line 38), before findingSuppressions (line 39) |dep:33a
- [x] 33c. Add skipTopicClassification: Boolean? field to PolicyRule.kt — position after topicClassification, before findingSuppressions |dep:33b
- [x] 33d. Add topicClassification: PolicyTopicClassification? field to PolicyDefaults.kt — position after pluginDetection (line 24), before findingSuppressions (line 25) |dep:33a
- [x] 33e. Add ReasonCode.TOPIC_DENIED(ReasonCategory.SECURITY) to enum in PolicyDecision.kt — append after HALLUCINATION_DETECTED in the SECURITY block (or after RESPONSE_PLUGIN_DETECTED if E36 not yet merged) |dep:none

### S2: Policy Validation (oag-policy)

- [x] 33f. Create TopicClassificationValidator.kt — internal fun PolicyTopicClassification.validate(base: String): List<ValidationError> using buildList pattern |dep:33a
- [x] 33g. Add endpoint_url structural validation in TopicClassificationValidator — scheme must be http/https, host non-null/non-blank, no userinfo component, warn on http |dep:33f
- [x] 33h. Add topic list validation in TopicClassificationValidator — cannot set both denied_topics and allowed_topics, at least one non-empty when enabled |dep:33f
- [x] 33i. Add topic label sanitization in TopicClassificationValidator — each label: non-blank, no control chars (isISOControl), max 256 chars |dep:33f
- [x] 33j. Add threshold/timeout/onError validation in TopicClassificationValidator — confidenceThreshold in (0.0, 1.0], endpointTimeoutMs positive and max 10_000, maxTextBytes positive, onError must be "deny" or "allow" |dep:33f
- [x] 33k. Wire TopicClassificationValidator into PolicyValidation.kt — add topicClassification?.validate("defaults.topic_classification") after pluginDetection block (line 73) |dep:33d,33f
- [x] 33l. Wire TopicClassificationValidator into RuleValidator.kt — add topicClassification?.validate() and skipTopicClassification mutual exclusion check after pluginDetection block (line 65) |dep:33b,33c,33f

### S3: User-Turn Extraction (oag-pipeline)

- [x] 33m. Create UserTurnExtractor.kt with extractUserTurnText(bodyText: String): String? — parse JSON, check for "messages" array, return null if not chat format |dep:none
- [x] 33n. Add reverse-iteration logic in UserTurnExtractor — iterate from end of messages array, capped at MAX_REVERSE_ITERATIONS=100, find first role=="user" |dep:33m
- [x] 33o. Add multimodal content handling in UserTurnExtractor — handle string content (return directly) and array content (concatenate type=="text" parts, ignore image parts) |dep:33m

### S4: Classification Client (oag-pipeline)

- [x] 33p. Create TopicClassifierClient fun interface and TopicClassificationException class in TopicClassifierClient.kt |dep:none
- [x] 33q. Create @Serializable TopicClassificationRequest(text, topics) and TopicClassificationResponse(topic, confidence) DTOs in TopicClassifierClient.kt |dep:33p
- [x] 33r. Create ExternalTopicClassifierClient class — inject SafeOutboundClient for SSRF validation instead of inlining, URI parsing, HttpClient.newBuilder().connectTimeout() |dep:23a,33p,33q
- [x] 33s. Add classify() method to ExternalTopicClassifierClient — HttpRequest.Builder with per-request timeout() covering full lifecycle (NNR-7), POST with JSON-serialized request body |dep:33r
- [x] 33t. Add HMAC-SHA256 signing to ExternalTopicClassifierClient.classify() — when signingSecret is set, compute signature via computeHmacSha256() and add X-Oag-Signature header |dep:33s
- [x] 33u. Add bounded response read to ExternalTopicClassifierClient.classify() — use BodyHandlers.ofInputStream() with readNBytes(maxResponseBytes+1), reject if over limit (NNR-10) |dep:33s
- [x] 33v. Add strict response deserialization to ExternalTopicClassifierClient.classify() — Json.decodeFromString<TopicClassificationResponse>, wrap all failures in TopicClassificationException |dep:33u

### S5: Pipeline Phase (oag-pipeline)

- [x] 33w. Create TopicClassificationAction enum (DENIED, ALLOWED, ERROR_DENY, ERROR_ALLOW) and TopicClassificationResult data class in TopicClassificationPhase.kt |dep:none
- [x] 33x. Create TopicClassificationPhase class implementing GatePhase, AuditEnrichable with companion PhaseKey — stage=INSPECT, skipWhenPolicyDenied=true, name="topic_classification" |dep:33w,33p
- [x] 33y. Add resolveTopicClassification() private helper — checks skipTopicClassification flag, then rule-level, then defaults; returns null if not enabled |dep:33x,33a
- [x] 33z. Implement evaluate() in TopicClassificationPhase — extract user-turn text via extractUserTurnText() with full-body fallback, truncate to maxTextBytes |dep:33x,33m
- [x] 34a. Add circuit breaker check in TopicClassificationPhase.evaluate() — circuitBreakerRegistry?.get(endpointUrl), if !allowRequest() throw TopicClassificationException routed through onError (NNR-8/9) |dep:33z
- [x] 34b. Add client call and error handling in TopicClassificationPhase.evaluate() — runCatching { client.classify() }, on failure route through onError policy (default "deny"), record breaker success/failure |dep:34a
- [x] 34c. Add topic match evaluation in TopicClassificationPhase — denied_topics mode: deny if topic in list with confidence >= threshold; allowed_topics mode: deny if topic NOT in list; case-insensitive comparison via lowercase(Locale.ROOT) |dep:34b
- [x] 34d. Add PhaseOutcome construction in TopicClassificationPhase.evaluate() — DENIED/ERROR_DENY -> denyPhase(TOPIC_DENIED), ALLOWED/ERROR_ALLOW -> Continue; store result in outputs |dep:34c
- [x] 34e. Implement enrichAudit() in TopicClassificationPhase — same resolution and classification logic, store result in outputs without denying (sensor-only for audit trail) |dep:34d

### S6: Body Buffering (oag-pipeline)

- [x] 34f. Modify resolveBufferableContentLength() in BodyInspection.kt — add topicClassificationActive boolean check (rule.topicClassification ?: defaults?.topicClassification, skip if skipTopicClassification, enabled == true), add || topicClassificationActive to needsBuffer expression |dep:33b,33d

### S7: Pipeline Wiring (oag-pipeline)

- [x] 34g. Add topicClassifierClient: TopicClassifierClient? = null parameter to buildHttpPipeline() in PipelineFactory.kt |dep:33p
- [x] 34h. Insert TopicClassificationPhase in buildHttpPipeline() after ContentInspectionPhase (line 73) and before CredentialsPhase (line 74) — if (topicClassifierClient != null) add(TopicClassificationPhase(policyService, topicClassifierClient, circuitBreakerRegistry)) |dep:34g,33x
- [x] 34i. Add topicClassifierClient: TopicClassifierClient? = null parameter to buildMitmPipeline() in PipelineFactory.kt |dep:33p
- [x] 34j. Insert TopicClassificationPhase in buildMitmPipeline() after ContentInspectionPhase (line 145) and before CredentialsPhase (line 146) — same conditional add pattern |dep:34i,33x

### S8: Audit (oag-audit)

- [x] 34k. Create AuditTopicClassification @Serializable data class in AuditModels.kt — fields: topic, confidence, action (String from enum label()), endpoint_latency_ms, error (all nullable except action) |dep:none
- [x] 34l. Add topicClassification: AuditTopicClassification? = null field to AuditEvent data class in AuditModels.kt — position after tokenUsage (line 186), nullable, no schema version bump |dep:34k

### S9: Audit Wiring (oag-proxy)

- [x] 34m. Add topicClassificationResult convenience property to RequestPipelineContext — get() = outputs.getOrNull(TopicClassificationPhase) |dep:33x
- [x] 34n. Wire topicClassification into buildAuditEvent() in RequestPipelineContext.kt — map TopicClassificationResult to AuditTopicClassification (topic, confidence, action.label(), latencyMs, error) |dep:34m,34k

### S10: Proxy Composition (oag-proxy)

- [x] 34o. Add DEFAULT_TOPIC_TIMEOUT_MS and DEFAULT_MAX_RESPONSE_BYTES private constants to HandlerFactory.kt |dep:none
- [x] 34p. Add topicClassifierClient construction block in HandlerFactory.kt — after mlClassifier block (line 157), construct ExternalTopicClassifierClient from policy defaults if enabled + endpoint_url set |dep:33r,34o
- [x] 34q. Pass topicClassifierClient to buildHttpPipeline() call in HandlerFactory.kt — add parameter after mlClassifier |dep:34p,34g
- [x] 34r. Pass topicClassifierClient to buildMitmPipeline() call in HandlerFactory.kt — add parameter after mlClassifier |dep:34p,34i

### S11: Verification

- [x] 34s. Verify signing_secret redaction in admin API — check AdminResponses.kt serialization, add @Transient to PolicyTopicClassification.signingSecret or create redacted DTO if exposed |dep:33a,34p

### S12: Tests — Validator

- [x] 34t. Write test: enabled without endpoint_url fails validation |dep:33f
- [x] 34u. Write test: invalid URL scheme (ftp://) fails validation |dep:33g
- [x] 34v. Write test: http scheme produces insecurity warning |dep:33g
- [x] 34w. Write test: URL with userinfo fails validation |dep:33g
- [x] 34x. Write test: both denied_topics and allowed_topics set fails |dep:33h
- [x] 34y. Write test: enabled with empty topic lists fails |dep:33h
- [x] 34z. Write test: confidence threshold 0.0 and 1.1 fail, 1.0 passes |dep:33j
- [x] 35a. Write test: timeout 0 and 11000 fail, 2000 passes |dep:33j
- [x] 35b. Write test: invalid onError ("retry") fails, "deny" and "allow" pass |dep:33j
- [x] 35c. Write test: control chars in topic label fails |dep:33i
- [x] 35d. Write test: topic label > 256 chars fails |dep:33i
- [x] 35e. Write test: blank topic label fails |dep:33i
- [x] 35f. Write test: fully valid config produces no errors |dep:33f

### S13: Tests — User-Turn Extraction

- [x] 35g. Write test: standard OpenAI chat format extracts last user message |dep:33m
- [x] 35h. Write test: multi-turn conversation extracts last user message (not first) |dep:33m
- [x] 35i. Write test: no user role in messages returns null |dep:33m
- [x] 35j. Write test: empty messages array returns null |dep:33m
- [x] 35k. Write test: non-JSON input returns null |dep:33m
- [x] 35l. Write test: multimodal content concatenates text parts, ignores image parts |dep:33o
- [x] 35m. Write test: messages array > 100 elements respects iteration cap (finds user in last 100 only) |dep:33n
- [x] 35n. Write test: non-chat JSON (no "messages" key) returns null |dep:33m
- [x] 35o. Write test: malformed message entry (non-object) gracefully skipped |dep:33m
- [x] 35p. Write test: user message with null content returns null |dep:33m

### S14: Tests — Classifier Client

- [x] 35q. Write test: successful classification returns correct topic and confidence |dep:33v
- [x] 35r. Write test: HMAC signature header present when signingSecret set |dep:33t
- [x] 35s. Write test: timeout enforcement — slow server triggers TopicClassificationException |dep:33s
- [x] 35t. Write test: response > 64KB rejected with TopicClassificationException |dep:33u
- [x] 35u. Write test: SSRF URL (127.0.0.1) rejected at construction with IllegalArgumentException |dep:33r
- [x] 35v. Write test: non-JSON response throws TopicClassificationException |dep:33v
- [x] 35w. Write test: HTTP 500 response throws TopicClassificationException |dep:33v
- [x] 35x. Write test: wrong JSON schema throws TopicClassificationException |dep:33v

### S15: Tests — Phase

- [x] 35y. Write test: denied topic returns PhaseOutcome.Deny with TOPIC_DENIED |dep:34d
- [x] 35z. Write test: non-denied topic returns PhaseOutcome.Continue |dep:34d
- [x] 36a. Write test: confidence below threshold returns Continue |dep:34c
- [x] 36b. Write test: on_error=deny blocks on client exception |dep:34b
- [x] 36c. Write test: on_error=allow continues on client exception |dep:34b
- [x] 36d. Write test: circuit breaker open triggers deny (default on_error) |dep:34a
- [x] 36e. Write test: circuit breaker open with on_error=allow continues |dep:34a
- [x] 36f. Write test: no config in rule or defaults returns Continue |dep:33y
- [x] 36g. Write test: no buffered body returns Continue |dep:33z
- [x] 36h. Write test: user-turn text preferred over full body (capture mock client arg) |dep:33z
- [x] 36i. Write test: case-insensitive topic comparison ("Finance" matches "finance") |dep:34c
- [x] 36j. Write test: result stored in PhaseOutputs after evaluation |dep:34d
- [x] 36k. Write test: enrichAudit stores result in outputs without throwing |dep:34e
- [x] 36l. Write test: allowed_topics mode denies unlisted topic |dep:34c
- [x] 36m. Write test: allowed_topics mode allows listed topic |dep:34c
- [x] 36n. Write test: skipTopicClassification=true skips evaluation |dep:33y

# E38: Output Format Validation — Schema Validation

## M14: Policy Model, Validation, and JSON Pointer ~~~~~~~~~~~~~~ ✓

### S1: Core Model

- [x] 37a. Create PolicySchemaValidation data class — @Serializable with schema, onFail, extractPath, parseExtractedJson |dep:none
- [x] 37b. Add schema_validation field to PolicyRule — nullable field with @SerialName, position after skipTopicClassification before findingSuppressions (or after skipHallucinationCheck if E37 not yet merged) |dep:37a
- [x] 37c. Add RESPONSE_SCHEMA_INVALID to ReasonCode enum (category: VALIDATION) — append after PATH_LENGTH_EXCEEDED in the VALIDATION block |dep:none
- [x] 37d. Add SCHEMA_VALIDATION_FAILED to WebhookEventType — new webhook event type |dep:none
- [x] 37e. Add schema_validation_failed to WebhookEventLabels.valid — enable webhook routing |dep:37d

### S2: Infrastructure

- [x] 37f. Add kotlinx-serialization-json dependency to oag-core — required for JsonElement API |dep:none
- [x] 37g. Create JsonPointer utility module — extractJsonPointer and validateJsonPointer functions |dep:37f

### S3: Validation & Integration

- [x] 37h. Create SchemaValidationValidator extension function — validation rules for schema blocks |dep:37a,37g
- [x] 37i. Wire SchemaValidationValidator into RuleValidator — call validator from PolicyRule.validate |dep:37b,37h
- [x] 37j. Add schema_validation field to PolicyDiff.diffRule — detect schema validation changes |dep:37b
- [x] 37k. Add schema_validation normalization to PolicyNormalizer — lowercase onFail, trim paths |dep:37b

### S4: Tests

- [x] 37l. Write PolicySchemaValidation serialization tests — YAML round-trip and defaults |dep:37a
- [x] 37m. Write SchemaValidationValidator test suite — validation rules for all constraints |dep:37h
- [x] 37n. Write JsonPointer test suite — RFC 6901 extraction and validation |dep:37g
- [x] 37o. Update PolicyDiffTest assertion count — change actualDiffEntries from 32 to 33 |dep:37j

## M15: Schema Validation Step with Library Spike ~~~~~~~~~~~~~~

### S1: Library Spike

- [-] 38a. Spike json-schema-validator library evaluation — test networknt vs optimumcode for binary size/constraints |dep:none |!blocked: needs manual library evaluation and native-image testing

### S2: Runtime

- [ ] 38b. Add json-schema-validator dependency to gradle — libs.versions.toml and oag-pipeline/build.gradle.kts |dep:38a
- [ ] 38c. Create CompiledSchemaValidation wrapper class — compiled validator with extracted path and onFail |dep:38b
- [ ] 38d. Create SchemaValidationStep response inspection — parse, extract, validate, handle errors |dep:38c
- [ ] 38e. Create SchemaValidationResult accumulator data class — track passed/errors/pathNotFound/parseFailure |dep:38d
- [ ] 38f. Wire SchemaValidationStep into ResponseInspectionPlan — check config and build step in chain |dep:38e
- [ ] 38g. Add schemaValidation field to InspectionAccumulator — store SchemaValidationResult |dep:38e,38f

### S3: Tests

- [ ] 38h. Write SchemaValidationStep unit tests — valid/invalid JSON, extract path, error handling |dep:38d
- [ ] 38i. Write CompiledSchemaValidation tests — compilation, security constraints ($ref depth/external) |dep:38c
- [ ] 38j. Write SchemaValidationStep chain integration tests — step ordering and short-circuits |dep:38f
- [ ] 38k. Verify GraalVM native-image compilation — test nativeCompile with validator library |dep:38b

## M16: Audit and Webhook Integration ~~~~~~~~~~~~~~

### S1: Audit Integration

- [ ] 39a. Add schema validation fields to AuditContentInspection — passed/errors/extractPath/pathNotFound |dep:none
- [ ] 39b. Add schemaValidationResult field to ResponseRelayResult — carry result through relay pipeline |dep:none
- [ ] 39c. Extract SchemaValidationResult in relayBuffered — populate ResponseRelayResult field |dep:39b
- [ ] 39d. Map SchemaValidationResult to audit fields in RelayAuditHelpers — populate AuditContentInspection |dep:39a,39c
- [ ] 39e. Update isNonTrivial() for schema validation — mark audit entries with schema results as non-trivial |dep:39d

### S2: Tests

- [ ] 39f. Write RelayAuditHelpers schema tests — result mapping and field nullability |dep:39d

## M17: End-to-End Integration Tests ~~~~~~~~~~~~~~

### S1: Integration Tests

- [ ] 40a. Write full-flow schema validation test — policy load through audit event emission |dep:39f
- [ ] 40b. Write security constraint tests — ReDoS detection, enum cardinality, schema size limits |dep:40a
- [ ] 40c. Write webhook dispatch test for schema validation — event firing and payload composition |dep:40a

# E39: Multi-Turn Session-Aware Security

## M18: Dense Score Window ~~~~~~~~~~~~~~

### S1: Dense Score Recording

- [x] 41a. Add ScoredTurn data class and update SessionState — totalTurnCount, scoredTurns ArrayDeque |dep:none
- [x] 41b. Update recordInjectionScore for dense recording — remove zero-score guard, use ScoredTurn |dep:41a
- [x] 41c. Update detectEscalation and injectionTrend for ScoredTurn — extract scores, return as scoredTurns |dep:41a
- [x] 41d. Update SessionRequestTrackerTest for dense window — zero-score turns, turn indices, eviction, totalTurnCount |dep:41a,41b,41c

## M19: Pattern Detection Engine ~~~~~~~~~~~~~~

### S1: Pattern Enum & Detection

- [x] 42a. Add EscalationPattern enum to oag-policy/core/ — SUSTAINED_ELEVATION, CRESCENDO with label() |dep:none
- [x] 42b. Add EscalationConfig, EscalationResult, and detection functions — detect orchestrator |dep:41a,42a
- [x] 42c. Add EscalationDetectionTest — sustained elevation, crescendo, pattern orchestration |dep:42b

## M20: Policy Configuration ~~~~~~~~~~~~~~

### S1: Policy Model & Validation

- [x] 43a. Add PolicyEscalation data class to PolicyInjectionScoring — enabled, windowSize, denyPatterns |dep:none
- [x] 43b. Add escalation validation to ContentInspectionValidator — windowSize range, pattern labels |dep:42a,43a
- [x] 43c. Write escalation policy validation tests — bounds, unknown patterns, valid configs |dep:43b

## M21: Audit & Wiring ~~~~~~~~~~~~~~ ✓

### S1: Integration

- [x] 44a. Add escalation fields to AuditContentInspection — pattern, windowScores, windowSize |dep:none
- [x] 44b. Wire escalation detection into BodyInspection.kt — read policy, call detector, boost, populate audit |dep:42b,43a,44a
- [x] 44c. Write escalation wiring integration tests — enabled policy detection, disabled backward compat |dep:44b

# E40: External Judge Primitive

## M1: Policy Layer ~~~~~~~~~~~~~~

- [x] 1. PolicyExternalJudge data class — add @Serializable data class with 8 nullable fields to PolicyInspection.kt |dep:none
- [x] 2. PolicyDefaults.externalJudge field — add external_judge field to PolicyDefaults in PolicyDefaults.kt |dep:1
- [x] 3. ContentInspectionValidator.validateExternalJudge — add validation function for endpoint, secret, timeouts, trigger modes in ContentInspectionValidator.kt |dep:1
- [x] 4. Wire validation into PolicyValidation — call externalJudge?.validate() in defaults validation |dep:3

## M2: Wire Format ~~~~~~~~~~~~~~

- [x] 5. ExternalJudgeModels.kt — create new file with JudgeRequest, JudgeResponse, JudgeDecision, JudgeResult, sanitize() extension |dep:none

## M3: Judge Client ~~~~~~~~~~~~~~

- [x] 6. ExternalJudgeClient.kt — create HTTP POST client with HMAC signing, SSRF check, bounded response reading |dep:5
- [x] 7. ExternalJudgeClientTest.kt — unit tests for SSRF prevention, timeouts, error classification |dep:6

## M4: Pipeline Integration ~~~~~~~~~~~~~~ ✓

- [x] 8. JudgeCallContext + JudgeInvoker — add data class and fun interface to ContentModels.kt in oag-pipeline |dep:5
- [x] 9. ContentInspectionResult judge fields — add 6 judge fields (score, decision, source, latency_ms, reason, error) |dep:8
- [x] 10. checkContentInspection signature — widen to accept judgeInvoker, judgeConfig, judgeContext parameters |dep:8
- [x] 11. checkContentInspectionScored judge logic — add runJudgeIfTriggered, resolveEffectiveScore, resolveJudgeDecisionLabel helpers |dep:10
- [x] 12. ContentInspectionPhase constructor — add judgeInvoker parameter |dep:8
- [x] 13. ContentInspectionPhase evaluate and enrichAudit — pass judgeInvoker through both paths |dep:12
- [x] 14. checkContentInspectionPhase and buildJudgeCallContext — add judgeInvoker param and context builder function |dep:12
- [x] 15. Deny-path AuditContentInspection — populate 6 judge fields from effectiveResult in inline construction |dep:9,14
- [x] 16. PipelineFactory buildHttpPipeline and buildMitmPipeline — add judgeInvoker parameter to both |dep:12
- [x] 17. HandlerFactory buildFullProxyHandler — construct ExternalJudgeClient from policy config with secretProvider |dep:6,2
- [x] 18. ComponentFactory buildProxySecretProvider — extract SecretProvider helper, pass to handler |dep:17

## M5: Audit ~~~~~~~~~~~~~~ ✓

- [x] 19. AuditContentInspection judge fields — add 6 judge fields to data class in AuditModels.kt |dep:9
- [x] 20. Verify allow-path audit flow — confirm no additional changes needed beyond deny-path |dep:15

## M6: Tests ~~~~~~~~~~~~~~ ✓

- [x] 21. PolicyExternalJudgeValidatorTest.kt — validation tests for all constraint combinations |dep:4
- [x] 22. ExternalJudgeModelsTest.kt — serialization round-trip, sanitization, bounds checking |dep:5
- [x] 23. ExternalJudgeIntegrationTest.kt — HttpServer integration, HMAC verification, error responses |dep:6
- [x] 24. ContentInspectorJudgeTest.kt — trigger modes, on_error handling, score resolution, field population |dep:11
- [x] 25. End-to-end integration test — full judge flow with mock policy and context |dep:24
