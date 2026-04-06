"""
Secrets Exposure Payloads for MCPloit.

Contains payloads and patterns for detecting hardcoded secrets,
credentials, API keys, and PII in MCP servers.

Target Challenges:
- Lab: Secrets PII (hardcoded credentials in source)
"""

from .base import Payload, PayloadCategory, PayloadSeverity


def get_payloads() -> list[Payload]:
    """Return all secrets exposure detection payloads."""
    return [
        # === BASE64 ENCODED SECRETS ===
        Payload(
            name="base64_credential_pattern",
            description="Detect base64-encoded credentials in source code",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"[A-Za-z0-9+/]{20,}={0,2}",
            variants=[
                r"atob\(['\"][A-Za-z0-9+/]+={0,2}['\"]\)",
                r"Buffer\.from\(['\"][A-Za-z0-9+/]+={0,2}['\"],\s*['\"]base64['\"]\)",
                r"base64\.b64decode\(['\"][A-Za-z0-9+/]+={0,2}['\"]\)",
                r"_S\(['\"][A-Za-z0-9+/]+={0,2}['\"]\)",  # Custom decoder function
            ],
            target_params=["source_code", "content", "script"],
            success_indicators=[
                "password", "secret", "credential", "admin",
                "api_key", "token", "database"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="base64_detection",
            context="Regex patterns to detect base64-encoded secrets",
        ),

        Payload(
            name="common_base64_secrets",
            description="Common credential values when base64-decoded",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload="YWRtaW4=",  # admin
            variants=[
                "cGFzc3dvcmQ=",  # password
                "cm9vdA==",  # root
                "c2VjcmV0",  # secret
                "YWRtaW46cGFzc3dvcmQ=",  # admin:password
                "dXNlcjpwYXNz",  # user:pass
            ],
            target_params=["encoded_value", "base64"],
            success_indicators=[
                "admin", "password", "root", "secret", "user"
            ],
            severity=PayloadSeverity.HIGH,
            technique="common_credentials",
            context="Common credentials that appear as base64 strings",
            encoding="base64",
        ),

        # === API KEY PATTERNS ===
        Payload(
            name="api_key_patterns",
            description="Regex patterns for common API key formats",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"sk-[a-zA-Z0-9]{32,}",
            variants=[
                r"pk-[a-zA-Z0-9]{32,}",  # Public key
                r"api_key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]",
                r"apikey['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]",
                r"api-key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]",
                r"x-api-key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]",
            ],
            target_params=["source_code", "content", "config"],
            success_indicators=[
                "sk-", "pk-", "api_key", "apikey", "api-key"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="api_key_regex",
            context="Regex patterns for API key detection",
        ),

        Payload(
            name="cloud_provider_keys",
            description="Patterns for cloud provider credentials",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
            variants=[
                r"ASIA[0-9A-Z]{16}",  # AWS Temp Key
                r"ABIA[0-9A-Z]{16}",  # AWS STS
                r"ACCA[0-9A-Z]{16}",  # AWS CloudFront
                r"aws_secret_access_key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
                r"AIza[0-9A-Za-z_-]{35}",  # Google API Key
                r"[a-z0-9]{32}-us[0-9]{1,2}",  # Mailchimp
            ],
            target_params=["source_code", "content", "config", "env"],
            success_indicators=[
                "AKIA", "ASIA", "aws_access_key", "aws_secret",
                "AIza", "gcp", "azure"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="cloud_key_detection",
            context="Detect AWS, GCP, Azure credential patterns",
        ),

        # === DATABASE CREDENTIALS ===
        Payload(
            name="database_connection_strings",
            description="Patterns for database connection strings",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"mongodb(\+srv)?://[^:]+:[^@]+@",
            variants=[
                r"postgres(ql)?://[^:]+:[^@]+@",
                r"mysql://[^:]+:[^@]+@",
                r"redis://:[^@]+@",
                r"Server=.+;.*Password=.+",
                r"jdbc:[a-z]+://.*password=",
                r"DATABASE_URL.*=.*://.*:.*@",
            ],
            target_params=["source_code", "content", "config", "connection_string"],
            success_indicators=[
                "mongodb://", "postgres://", "mysql://", "redis://",
                "Password=", "password=", "DATABASE_URL"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="connection_string_detection",
            context="Detect database credentials in connection strings",
        ),

        Payload(
            name="database_credential_vars",
            description="Common database credential variable patterns",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"DB_PASSWORD\s*[:=]\s*['\"][^'\"]+['\"]",
            variants=[
                r"DATABASE_PASSWORD\s*[:=]\s*['\"][^'\"]+['\"]",
                r"MYSQL_PASSWORD\s*[:=]\s*['\"][^'\"]+['\"]",
                r"POSTGRES_PASSWORD\s*[:=]\s*['\"][^'\"]+['\"]",
                r"MONGO_PASSWORD\s*[:=]\s*['\"][^'\"]+['\"]",
                r"REDIS_PASSWORD\s*[:=]\s*['\"][^'\"]+['\"]",
            ],
            target_params=["source_code", "content", "env", "config"],
            success_indicators=[
                "DB_PASSWORD", "DATABASE_PASSWORD", "MYSQL_PASSWORD",
                "POSTGRES_PASSWORD", "MONGO_PASSWORD"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="db_credential_vars",
            context="Common environment variable names for database passwords",
        ),

        # === TOKEN PATTERNS ===
        Payload(
            name="jwt_token_pattern",
            description="Pattern for JWT tokens in source code",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            variants=[
                r"Bearer\s+eyJ[a-zA-Z0-9_-]+",
                r"jwt['\"]?\s*[:=]\s*['\"]eyJ[a-zA-Z0-9_-]+",
                r"token['\"]?\s*[:=]\s*['\"]eyJ[a-zA-Z0-9_-]+",
            ],
            target_params=["source_code", "content", "headers"],
            success_indicators=[
                "eyJ", "Bearer", "jwt", "token"
            ],
            severity=PayloadSeverity.HIGH,
            technique="jwt_detection",
            context="Detect hardcoded JWT tokens",
        ),

        Payload(
            name="oauth_token_patterns",
            description="Patterns for OAuth tokens and secrets",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"client_secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]",
            variants=[
                r"client_id['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]",
                r"oauth_token['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]",
                r"refresh_token['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]",
                r"access_token['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]",
            ],
            target_params=["source_code", "content", "config"],
            success_indicators=[
                "client_secret", "client_id", "oauth", "refresh_token",
                "access_token"
            ],
            severity=PayloadSeverity.HIGH,
            technique="oauth_detection",
            context="Detect OAuth credentials in source",
        ),

        # === PRIVATE KEYS ===
        Payload(
            name="private_key_patterns",
            description="Patterns for private keys in source code",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            variants=[
                r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
                r"-----BEGIN CERTIFICATE-----",
                r"ssh-rsa AAAA[a-zA-Z0-9+/]+",
                r"ssh-ed25519 AAAA[a-zA-Z0-9+/]+",
            ],
            target_params=["source_code", "content", "file"],
            success_indicators=[
                "PRIVATE KEY", "PGP PRIVATE", "ssh-rsa", "ssh-ed25519",
                "CERTIFICATE"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="private_key_detection",
            context="Detect private keys embedded in code",
        ),

        # === PII PATTERNS ===
        Payload(
            name="email_patterns",
            description="Patterns for email addresses (potential admin emails)",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"admin@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            variants=[
                r"root@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                r"support@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                r"[a-zA-Z0-9._%+-]+@(gmail|yahoo|hotmail|outlook)\.[a-zA-Z]{2,}",
                r"admin_email['\"]?\s*[:=]\s*['\"][^'\"]+@",
            ],
            target_params=["source_code", "content"],
            success_indicators=[
                "admin@", "root@", "support@", "@gmail", "@internal"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="pii_email_detection",
            context="Detect hardcoded admin or internal email addresses",
        ),

        # === GENERIC CREDENTIAL PATTERNS ===
        Payload(
            name="password_variable_patterns",
            description="Common patterns for password variables",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"password['\"]?\s*[:=]\s*['\"][^'\"]{4,}['\"]",
            variants=[
                r"passwd['\"]?\s*[:=]\s*['\"][^'\"]+['\"]",
                r"pwd['\"]?\s*[:=]\s*['\"][^'\"]+['\"]",
                r"secret['\"]?\s*[:=]\s*['\"][^'\"]+['\"]",
                r"credentials?['\"]?\s*[:=]\s*['\"][^'\"]+['\"]",
                r"auth['\"]?\s*[:=]\s*['\"][^'\"]+['\"]",
            ],
            target_params=["source_code", "content", "config"],
            success_indicators=[
                "password", "passwd", "pwd", "secret", "credential", "auth"
            ],
            severity=PayloadSeverity.HIGH,
            technique="password_detection",
            context="Detect hardcoded password assignments",
        ),

        Payload(
            name="internal_url_patterns",
            description="Patterns for internal/admin URLs that may leak info",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"https?://localhost[:/]",
            variants=[
                r"https?://127\.0\.0\.1[:/]",
                r"https?://192\.168\.\d+\.\d+[:/]",
                r"https?://10\.\d+\.\d+\.\d+[:/]",
                r"https?://172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+[:/]",
                r"https?://[a-zA-Z0-9-]+\.internal[:/.]",
                r"https?://[a-zA-Z0-9-]+\.local[:/.]",
            ],
            target_params=["source_code", "content", "config"],
            success_indicators=[
                "localhost", "127.0.0.1", "192.168.", "10.",
                ".internal", ".local", "admin"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="internal_url_detection",
            context="Detect internal/development URLs that may expose infrastructure",
        ),

        # === WEBHOOK/ENDPOINT SECRETS ===
        Payload(
            name="webhook_secret_patterns",
            description="Patterns for webhook secrets and signing keys",
            category=PayloadCategory.SECRETS_EXPOSURE,
            payload=r"webhook_secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]",
            variants=[
                r"signing_secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]",
                r"signature_key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]",
                r"hmac_key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]",
                r"encryption_key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]+['\"]",
            ],
            target_params=["source_code", "content", "config"],
            success_indicators=[
                "webhook_secret", "signing_secret", "signature_key",
                "hmac_key", "encryption_key"
            ],
            severity=PayloadSeverity.HIGH,
            technique="webhook_secret_detection",
            context="Detect webhook and signing secrets",
        ),
    ]
