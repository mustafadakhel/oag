package com.mustafadakhel.oag.app

internal object CliFlags {

    // Help aliases
    const val HELP_LONG = "--help"
    const val HELP_SHORT = "-h"
    const val FLAG_PREFIX = "--"

    // Common
    const val JSON = "--json"
    const val VERBOSE = "--verbose"
    const val POLICY = "--policy"
    const val CONFIG_DIR = "--config-dir"

    // Run / Doctor
    const val PORT = "--port"
    const val LOG = "--log"
    const val AGENT = "--agent"
    const val SESSION = "--session"
    const val MAX_THREADS = "--max-threads"
    const val DRY_RUN = "--dry-run"
    const val WATCH = "--watch"

    // Security
    const val POLICY_PUBLIC_KEY = "--policy-public-key"
    const val POLICY_REQUIRE_SIGNATURE = "--policy-require-signature"
    const val BLOCK_IP_LITERALS = "--block-ip-literals"
    const val ENFORCE_REDIRECT_POLICY = "--enforce-redirect-policy"
    const val BLOCK_PRIVATE_RESOLVED_IPS = "--block-private-resolved-ips"

    // Secrets
    const val SECRET_PREFIX = "--secret-prefix"
    const val SECRET_PROVIDER = "--secret-provider"
    const val SECRET_DIR = "--secret-dir"
    const val OAUTH2_TOKEN_URL = "--oauth2-token-url"
    const val OAUTH2_CLIENT_ID = "--oauth2-client-id"
    const val OAUTH2_CLIENT_SECRET = "--oauth2-client-secret"
    const val OAUTH2_SCOPE = "--oauth2-scope"

    // Timeouts
    const val CONNECT_TIMEOUT_MS = "--connect-timeout-ms"
    const val READ_TIMEOUT_MS = "--read-timeout-ms"
    const val DRAIN_TIMEOUT_MS = "--drain-timeout-ms"

    // TLS
    const val TLS_INSPECT = "--tls-inspect"
    const val TLS_CA_CERT_PATH = "--tls-ca-cert-path"

    // mTLS
    const val MTLS_CA_CERT = "--mtls-ca-cert"
    const val MTLS_KEYSTORE = "--mtls-keystore"
    const val MTLS_KEYSTORE_PASSWORD = "--mtls-keystore-password"

    // Signed headers
    const val AGENT_SIGNING_SECRET = "--agent-signing-secret"
    const val REQUIRE_SIGNED_HEADERS = "--require-signed-headers"

    // Admin
    const val ADMIN_PORT = "--admin-port"
    const val ADMIN_ALLOWED_IPS = "--admin-allowed-ips"
    const val ADMIN_TOKEN = "--admin-token"
    const val ADMIN_RELOAD_COOLDOWN_MS = "--admin-reload-cooldown-ms"

    // Circuit breaker
    const val CIRCUIT_BREAKER_THRESHOLD = "--circuit-breaker-threshold"
    const val CIRCUIT_BREAKER_RESET_MS = "--circuit-breaker-reset-ms"
    const val CIRCUIT_BREAKER_HALF_OPEN_PROBES = "--circuit-breaker-half-open-probes"

    // Request ID
    const val INJECT_REQUEST_ID = "--inject-request-id"
    const val REQUEST_ID_HEADER = "--request-id-header"

    // Connection pool
    const val POOL_MAX_IDLE = "--pool-max-idle"
    const val POOL_IDLE_TIMEOUT_MS = "--pool-idle-timeout-ms"

    // Log rotation
    const val LOG_MAX_SIZE_MB = "--log-max-size-mb"
    const val LOG_MAX_FILES = "--log-max-files"
    const val LOG_COMPRESS = "--log-compress"
    const val LOG_ROTATION_INTERVAL = "--log-rotation-interval"

    // Webhook
    const val WEBHOOK_URL = "--webhook-url"
    const val WEBHOOK_EVENTS = "--webhook-events"
    const val WEBHOOK_TIMEOUT_MS = "--webhook-timeout-ms"
    const val WEBHOOK_SIGNING_SECRET = "--webhook-signing-secret"

    // Velocity
    const val VELOCITY_SPIKE_THRESHOLD = "--velocity-spike-threshold"

    // Plugins
    const val PLUGIN_PROVIDER = "--plugin-provider"

    // Policy fetch
    const val POLICY_URL = "--policy-url"
    const val POLICY_FETCH_INTERVAL_S = "--policy-fetch-interval-s"
    const val INTEGRITY_CHECK_INTERVAL_S = "--integrity-check-interval-s"

    // OTel
    const val OTEL_EXPORTER = "--otel-exporter"
    const val OTEL_ENDPOINT = "--otel-endpoint"
    const val OTEL_HEADERS = "--otel-headers"
    const val OTEL_TIMEOUT_MS = "--otel-timeout-ms"
    const val OTEL_SERVICE_NAME = "--otel-service-name"

    // Simulate
    const val METHOD = "--method"
    const val HOST = "--host"
    const val PATH = "--path"
    const val SCHEME = "--scheme"
    const val BATCH = "--batch"

    // Test
    const val CASES = "--cases"

    // Explain
    const val REQUEST = "--request"

    // Bundle
    const val OUT = "--out"
    const val SIGN_KEY = "--sign-key"
    const val KEY_ID = "--key-id"

    // Verify
    const val VERIFY = "--verify"
    const val BUNDLE = "--bundle"
    const val PUBLIC_KEY = "--public-key"
}

object CliDefaults {
    const val POLICY_FILE = "policy.yaml"
    const val SECRETS_DIR = "secrets"
    const val LOGS_DIR = "logs"
    const val AUDIT_FILE = "audit.jsonl"
}
