package com.mustafadakhel.oag.audit

internal object AuditJsonKeys {

    // Envelope (shared across event types)
    const val TIMESTAMP = "timestamp"
    const val SCHEMA_VERSION = "schema_version"
    const val OAG_VERSION = "oag_version"
    const val POLICY_HASH = "policy_hash"
    const val AGENT_ID = "agent_id"
    const val SESSION_ID = "session_id"
    const val EVENT_TYPE = "event_type"
    const val REQUEST_ID = "request_id"

    // Trace
    const val TRACE = "trace"
    const val TRACE_ID = "trace_id"
    const val SPAN_ID = "span_id"
    const val TRACE_FLAGS = "trace_flags"

    // Decision
    const val DECISION = "decision"
    const val ACTION = "action"
    const val RULE_ID = "rule_id"
    const val REASON_CODE = "reason_code"

    // Request
    const val REQUEST = "request"
    const val HOST = "host"
    const val PORT = "port"
    const val SCHEME = "scheme"
    const val METHOD = "method"
    const val PATH = "path"
    const val BYTES_OUT = "bytes_out"
    const val RESOLVED_IPS = "resolved_ips"

    // Response
    const val RESPONSE = "response"
    const val BYTES_IN = "bytes_in"
    const val STATUS = "status"

    // Redirect chain
    const val REDIRECT_CHAIN = "redirect_chain"
    const val LOCATION = "location"
    const val TARGET_HOST = "target_host"
    const val TARGET_PORT = "target_port"
    const val TARGET_SCHEME = "target_scheme"
    const val TARGET_PATH = "target_path"

    // Secrets
    const val SECRETS = "secrets"
    const val INJECTION_ATTEMPTED = "injection_attempted"
    const val INJECTED = "injected"
    const val SECRET_IDS = "secret_ids"
    const val SECRET_VERSIONS = "secret_versions"

    // Error
    const val ERRORS = "errors"
    const val CODE = "code"
    const val MESSAGE = "message"

    // Content inspection
    const val CONTENT_INSPECTION = "content_inspection"
    const val BODY_INSPECTED = "body_inspected"
    const val BODY_NORMALIZED = "body_normalized"
    const val INJECTION_PATTERNS_MATCHED = "injection_patterns_matched"
    const val URL_ENTROPY_SCORE = "url_entropy_score"
    const val DNS_ENTROPY_SCORE = "dns_entropy_score"
    const val DATA_BUDGET_USED_BYTES = "data_budget_used_bytes"
    const val RESPONSE_TRUNCATED = "response_truncated"
    const val STREAMING_PATTERNS_MATCHED = "streaming_patterns_matched"
    const val INJECTION_SCORE = "injection_score"
    const val INJECTION_SIGNALS = "injection_signals"
    const val CREDENTIALS_DETECTED = "credentials_detected"
    const val DATA_CLASSIFICATION_MATCHES = "data_classification_matches"
    const val DATA_CLASSIFICATION_CATEGORIES = "data_classification_categories"
    const val PATH_ENTROPY_SCORE = "path_entropy_score"
    const val PATH_TRAVERSAL_DETECTED = "path_traversal_detected"

    // Header rewrites
    const val HEADER_REWRITES = "header_rewrites"
    const val HEADER = "header"

    // Response rewrites
    const val RESPONSE_REWRITES = "response_rewrites"
    const val PATTERN = "pattern"
    const val REDACTION_COUNT = "redaction_count"

    // Structured payload
    const val STRUCTURED_PAYLOAD = "structured_payload"
    const val PROTOCOL = "protocol"
    const val OPERATION_NAME = "operation_name"
    const val OPERATION_TYPE = "operation_type"

    // WebSocket session
    const val WEB_SOCKET_SESSION = "web_socket_session"
    const val FRAME_COUNT = "frame_count"
    const val CLIENT_FRAMES = "client_frames"
    const val SERVER_FRAMES = "server_frames"
    const val DETECTED_PATTERNS = "detected_patterns"

    // AuditEvent top-level fields
    const val RETRY_COUNT = "retry_count"
    const val TAGS = "tags"
    const val AGENT_PROFILE = "agent_profile"
    const val PHASE_TIMINGS = "phase_timings"
    const val DRY_RUN_OVERRIDE = "dry_run_override"

    // Startup config
    const val CONFIG = "config"
    const val CONFIG_FINGERPRINT = "config_fingerprint"
    const val POLICY_PATH = "policy_path"
    const val POLICY_PUBLIC_KEY_PATH = "policy_public_key_path"
    const val POLICY_REQUIRE_SIGNATURE = "policy_require_signature"
    const val LOG_PATH = "log_path"
    const val LISTEN_HOST = "listen_host"
    const val LISTEN_PORT = "listen_port"
    const val MAX_THREADS = "max_threads"
    const val SECRET_ENV_PREFIX = "secret_env_prefix"
    const val SECRET_PROVIDER = "secret_provider"
    const val SECRET_FILE_DIR = "secret_file_dir"
    const val DRY_RUN = "dry_run"
    const val BLOCK_IP_LITERALS = "block_ip_literals"
    const val ENFORCE_REDIRECT_POLICY = "enforce_redirect_policy"
    const val BLOCK_PRIVATE_RESOLVED_IPS = "block_private_resolved_ips"
    const val CONNECT_TIMEOUT_MS = "connect_timeout_ms"
    const val READ_TIMEOUT_MS = "read_timeout_ms"
    const val OTEL_EXPORTER = "otel_exporter"
    const val OTEL_ENDPOINT = "otel_endpoint"
    const val OTEL_HEADERS_KEYS = "otel_headers_keys"
    const val OTEL_TIMEOUT_MS = "otel_timeout_ms"
    const val OTEL_SERVICE_NAME = "otel_service_name"

    // Policy reload
    const val PREVIOUS_POLICY_HASH = "previous_policy_hash"
    const val NEW_POLICY_HASH = "new_policy_hash"
    const val CHANGED = "changed"
    const val SUCCESS = "success"
    const val ERROR_MESSAGE = "error_message"
    const val TRIGGER = "trigger"

    // Circuit breaker
    const val PREVIOUS_STATE = "previous_state"
    const val NEW_STATE = "new_state"

    // Policy fetch
    const val SOURCE_URL = "source_url"
    const val CONTENT_HASH = "content_hash"

    // Admin access
    const val ENDPOINT = "endpoint"
    const val SOURCE_IP = "source_ip"
    const val ALLOWED = "allowed"

    // Integrity check
    const val POLICY_HASH_MATCH = "policy_hash_match"
    const val CONFIG_FINGERPRINT_MATCH = "config_fingerprint_match"

    // Token usage
    const val TOKEN_USAGE = "token_usage"
    const val PROMPT_TOKENS = "prompt_tokens"
    const val COMPLETION_TOKENS = "completion_tokens"
    const val TOTAL_TOKENS = "total_tokens"

    // Tool
    const val TOOL = "tool"
    const val NAME = "name"
    const val PARAMETER_KEYS = "parameter_keys"
    const val PARAMETERS = "parameters"
    const val RESPONSE_BYTES = "response_bytes"
    const val DURATION_MS = "duration_ms"
    const val ERROR_CODE = "error_code"
}
