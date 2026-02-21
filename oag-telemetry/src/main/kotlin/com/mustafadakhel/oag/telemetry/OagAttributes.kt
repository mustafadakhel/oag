package com.mustafadakhel.oag.telemetry

import io.opentelemetry.api.common.AttributeKey

internal object OagAttributes {

    const val LOGGER_SCOPE = "oag.audit"

    const val BODY_REQUEST = "oag.audit.request"
    const val BODY_TOOL = "oag.audit.tool"
    const val BODY_STARTUP = "oag.audit.startup"
    const val BODY_POLICY_RELOAD = "oag.audit.policy_reload"
    const val BODY_CIRCUIT_BREAKER = "oag.audit.circuit_breaker"
    const val BODY_POLICY_FETCH = "oag.audit.policy_fetch"
    const val BODY_ADMIN_ACCESS = "oag.audit.admin_access"
    const val BODY_INTEGRITY_CHECK = "oag.audit.integrity_check"

    // Resource
    val SERVICE_NAME: AttributeKey<String> = AttributeKey.stringKey("service.name")
    val SERVICE_VERSION: AttributeKey<String> = AttributeKey.stringKey("service.version")

    // Common
    val EVENT_TYPE: AttributeKey<String> = AttributeKey.stringKey("oag.event.type")
    val POLICY_HASH: AttributeKey<String> = AttributeKey.stringKey("oag.policy.hash")
    val AGENT_ID: AttributeKey<String> = AttributeKey.stringKey("oag.agent_id")
    val SESSION_ID: AttributeKey<String> = AttributeKey.stringKey("oag.session_id")

    // Decision
    val DECISION_ACTION: AttributeKey<String> = AttributeKey.stringKey("oag.decision.action")
    val DECISION_REASON_CODE: AttributeKey<String> = AttributeKey.stringKey("oag.decision.reason_code")
    val DECISION_RULE_ID: AttributeKey<String> = AttributeKey.stringKey("oag.decision.rule_id")
    val DRY_RUN_OVERRIDE: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.decision.dry_run_override")

    // Secrets
    val SECRETS_INJECTION_ATTEMPTED: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.secrets.injection_attempted")
    val SECRETS_INJECTED: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.secrets.injected")
    val SECRETS_IDS: AttributeKey<List<String>> = AttributeKey.stringArrayKey("oag.secrets.ids")
    val SECRETS_VERSIONS: AttributeKey<List<String>> = AttributeKey.stringArrayKey("oag.secrets.versions")

    // HTTP semantic conventions
    val HTTP_REQUEST_METHOD: AttributeKey<String> = AttributeKey.stringKey("http.request.method")
    val HTTP_RESPONSE_STATUS_CODE: AttributeKey<Long> = AttributeKey.longKey("http.response.status_code")
    val URL_SCHEME: AttributeKey<String> = AttributeKey.stringKey("url.scheme")
    val URL_PATH: AttributeKey<String> = AttributeKey.stringKey("url.path")
    val SERVER_ADDRESS: AttributeKey<String> = AttributeKey.stringKey("server.address")
    val SERVER_PORT: AttributeKey<Long> = AttributeKey.longKey("server.port")

    // Request
    val REQUEST_BYTES_OUT: AttributeKey<Long> = AttributeKey.longKey("oag.request.bytes_out")
    val REQUEST_RESOLVED_IPS: AttributeKey<List<String>> = AttributeKey.stringArrayKey("oag.request.resolved_ips")

    // Response
    val RESPONSE_BYTES_IN: AttributeKey<Long> = AttributeKey.longKey("oag.response.bytes_in")

    // Redirect
    val REDIRECT_COUNT: AttributeKey<Long> = AttributeKey.longKey("oag.redirect.count")
    val REDIRECT_LOCATIONS: AttributeKey<List<String>> = AttributeKey.stringArrayKey("oag.redirect.locations")

    // Errors
    val ERRORS: AttributeKey<List<String>> = AttributeKey.stringArrayKey("oag.errors")

    // Tool
    val TOOL_NAME: AttributeKey<String> = AttributeKey.stringKey("oag.tool.name")
    val TOOL_PARAMETER_KEYS: AttributeKey<List<String>> = AttributeKey.stringArrayKey("oag.tool.parameter_keys")
    val TOOL_RESPONSE_BYTES: AttributeKey<Long> = AttributeKey.longKey("oag.tool.response_bytes")
    val TOOL_DURATION_MS: AttributeKey<Long> = AttributeKey.longKey("oag.tool.duration_ms")
    val TOOL_ERROR_CODE: AttributeKey<String> = AttributeKey.stringKey("oag.tool.error_code")

    // Phase timings
    val PHASE_POLICY_EVALUATION_MS: AttributeKey<Double> = AttributeKey.doubleKey("oag.phase.policy_evaluation_ms")
    val PHASE_DNS_RESOLUTION_MS: AttributeKey<Double> = AttributeKey.doubleKey("oag.phase.dns_resolution_ms")
    val PHASE_UPSTREAM_CONNECT_MS: AttributeKey<Double> = AttributeKey.doubleKey("oag.phase.upstream_connect_ms")
    val PHASE_REQUEST_RELAY_MS: AttributeKey<Double> = AttributeKey.doubleKey("oag.phase.request_relay_ms")
    val PHASE_RESPONSE_RELAY_MS: AttributeKey<Double> = AttributeKey.doubleKey("oag.phase.response_relay_ms")
    val PHASE_SECRET_MATERIALIZATION_MS: AttributeKey<Double> = AttributeKey.doubleKey("oag.phase.secret_materialization_ms")
    val PHASE_TOTAL_MS: AttributeKey<Double> = AttributeKey.doubleKey("oag.phase.total_ms")

    // Policy reload
    val POLICY_RELOAD_PREVIOUS_HASH: AttributeKey<String> = AttributeKey.stringKey("oag.policy_reload.previous_hash")
    val POLICY_RELOAD_NEW_HASH: AttributeKey<String> = AttributeKey.stringKey("oag.policy_reload.new_hash")
    val POLICY_RELOAD_CHANGED: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.policy_reload.changed")
    val POLICY_RELOAD_SUCCESS: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.policy_reload.success")
    val POLICY_RELOAD_ERROR_MESSAGE: AttributeKey<String> = AttributeKey.stringKey("oag.policy_reload.error_message")
    val POLICY_RELOAD_TRIGGER: AttributeKey<String> = AttributeKey.stringKey("oag.policy_reload.trigger")

    // Circuit breaker
    val CIRCUIT_BREAKER_HOST: AttributeKey<String> = AttributeKey.stringKey("oag.circuit_breaker.host")
    val CIRCUIT_BREAKER_PREVIOUS_STATE: AttributeKey<String> = AttributeKey.stringKey("oag.circuit_breaker.previous_state")
    val CIRCUIT_BREAKER_NEW_STATE: AttributeKey<String> = AttributeKey.stringKey("oag.circuit_breaker.new_state")

    // Policy fetch
    val POLICY_FETCH_SOURCE_URL: AttributeKey<String> = AttributeKey.stringKey("oag.policy_fetch.source_url")
    val POLICY_FETCH_SUCCESS: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.policy_fetch.success")
    val POLICY_FETCH_CHANGED: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.policy_fetch.changed")
    val POLICY_FETCH_CONTENT_HASH: AttributeKey<String> = AttributeKey.stringKey("oag.policy_fetch.content_hash")
    val POLICY_FETCH_ERROR_MESSAGE: AttributeKey<String> = AttributeKey.stringKey("oag.policy_fetch.error_message")

    // Admin access
    val ADMIN_ENDPOINT: AttributeKey<String> = AttributeKey.stringKey("oag.admin.endpoint")
    val ADMIN_SOURCE_IP: AttributeKey<String> = AttributeKey.stringKey("oag.admin.source_ip")
    val ADMIN_ALLOWED: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.admin.allowed")

    // Integrity check
    val INTEGRITY_STATUS: AttributeKey<String> = AttributeKey.stringKey("oag.integrity.status")
    val INTEGRITY_POLICY_HASH_MATCH: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.integrity.policy_hash_match")
    val INTEGRITY_CONFIG_FINGERPRINT_MATCH: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.integrity.config_fingerprint_match")

    // Token usage
    val TOKEN_PROMPT_TOKENS: AttributeKey<Long> = AttributeKey.longKey("oag.token_usage.prompt_tokens")
    val TOKEN_COMPLETION_TOKENS: AttributeKey<Long> = AttributeKey.longKey("oag.token_usage.completion_tokens")
    val TOKEN_TOTAL_TOKENS: AttributeKey<Long> = AttributeKey.longKey("oag.token_usage.total_tokens")

    // Config
    val CONFIG_POLICY_PATH: AttributeKey<String> = AttributeKey.stringKey("oag.config.policy_path")
    val CONFIG_POLICY_REQUIRE_SIGNATURE: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.config.policy_require_signature")
    val CONFIG_LISTEN_HOST: AttributeKey<String> = AttributeKey.stringKey("oag.config.listen_host")
    val CONFIG_LISTEN_PORT: AttributeKey<Long> = AttributeKey.longKey("oag.config.listen_port")
    val CONFIG_MAX_THREADS: AttributeKey<Long> = AttributeKey.longKey("oag.config.max_threads")
    val CONFIG_SECRET_ENV_PREFIX: AttributeKey<String> = AttributeKey.stringKey("oag.config.secret_env_prefix")
    val CONFIG_SECRET_PROVIDER: AttributeKey<String> = AttributeKey.stringKey("oag.config.secret_provider")
    val CONFIG_DRY_RUN: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.config.dry_run")
    val CONFIG_BLOCK_IP_LITERALS: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.config.block_ip_literals")
    val CONFIG_ENFORCE_REDIRECT_POLICY: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.config.enforce_redirect_policy")
    val CONFIG_BLOCK_PRIVATE_RESOLVED_IPS: AttributeKey<Boolean> = AttributeKey.booleanKey("oag.config.block_private_resolved_ips")
    val CONFIG_CONNECT_TIMEOUT_MS: AttributeKey<Long> = AttributeKey.longKey("oag.config.connect_timeout_ms")
    val CONFIG_READ_TIMEOUT_MS: AttributeKey<Long> = AttributeKey.longKey("oag.config.read_timeout_ms")
    val CONFIG_POLICY_PUBLIC_KEY_PATH: AttributeKey<String> = AttributeKey.stringKey("oag.config.policy_public_key_path")
    val CONFIG_LOG_PATH: AttributeKey<String> = AttributeKey.stringKey("oag.config.log_path")
    val CONFIG_SECRET_FILE_DIR: AttributeKey<String> = AttributeKey.stringKey("oag.config.secret_file_dir")
    val CONFIG_OTEL_EXPORTER: AttributeKey<String> = AttributeKey.stringKey("oag.config.otel_exporter")
    val CONFIG_OTEL_ENDPOINT: AttributeKey<String> = AttributeKey.stringKey("oag.config.otel_endpoint")
    val CONFIG_OTEL_HEADERS_KEYS: AttributeKey<List<String>> = AttributeKey.stringArrayKey("oag.config.otel_headers_keys")
    val CONFIG_OTEL_TIMEOUT_MS: AttributeKey<Long> = AttributeKey.longKey("oag.config.otel_timeout_ms")
    val CONFIG_OTEL_SERVICE_NAME: AttributeKey<String> = AttributeKey.stringKey("oag.config.otel_service_name")
}
