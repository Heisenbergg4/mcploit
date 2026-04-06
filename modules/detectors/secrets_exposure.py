"""Secrets Exposure vulnerability detector.

Detects potential secrets/credentials exposure:
- Credential-related resources and tools
- Internal/system protocol URIs
- API key handling
- Database credentials
- AWS/cloud credentials
"""

import re
from .base_detector import (
    BaseDetector,
    DetectorContext,
    Vulnerability,
    Severity,
    Confidence,
)


class SecretsExposureDetector(BaseDetector):
    """Detects secrets and credential exposure vulnerabilities."""

    name = "Secrets Exposure Detector"
    description = "Detects potential secrets, credentials, and sensitive data exposure"
    vulnerability_types = ["secrets_exposure", "credential_leak", "sensitive_data"]

    # Credential-related patterns.
    # "credential" and "secret" use word-boundary regex to avoid matching
    # "credentials" (generic), "secretary", etc.
    # "session" removed from this list — it's common in any web-framework MCP server
    # and belongs only in the SESSION_PATTERNS check where it has more context.
    CREDENTIAL_PATTERNS = [
        (r"\bcredential\b", True),    # word-boundary
        (r"\bpassword\b", True),      # word-boundary
        ("passwd", False),
        (r"\bsecret\b", True),        # word-boundary
        ("api_key", False),
        ("apikey", False),
        ("api-key", False),
        ("access_key", False),
        ("secret_key", False),
        ("private_key", False),
        ("auth_token", False),
        ("bearer", False),
        ("oauth", False),
        ("jwt", False),
        ("cookie", False),
    ]

    # Cloud/service credential patterns
    CLOUD_CREDENTIAL_PATTERNS = [
        ("aws", False),
        ("azure", False),
        ("gcp", False),
        ("google_cloud", False),
        ("s3", False),
        ("dynamodb", False),
        ("lambda", False),
        ("iam", False),
        ("arn:", False),
        ("AKIA", False),  # AWS access key prefix
        ("ABIA", False),  # AWS access key prefix
        ("ACCA", False),  # AWS access key prefix
    ]

    # Database credential patterns
    DATABASE_PATTERNS = [
        ("database", False),
        ("db_password", False),
        ("db_user", False),
        ("connection_string", False),
        ("mongodb", False),
        ("postgres", False),
        ("mysql", False),
        ("redis", False),
        ("elasticsearch", False),
    ]

    # Internal/system protocol patterns
    INTERNAL_PROTOCOL_PATTERNS = [
        (r"internal://", True),
        (r"system://", True),
        (r"admin://", True),
        (r"private://", True),
        (r"secret://", True),
        (r"config://", True),
        (r"env://", True),
    ]

    # Sensitive file patterns
    SENSITIVE_FILE_PATTERNS = [
        (r"\.env", True),
        (r"\.pem", True),
        (r"\.key", True),
        (r"\.crt", True),
        (r"\.pfx", True),
        (r"id_rsa", True),
        (r"id_dsa", True),
        (r"id_ecdsa", True),
        (r"\.ssh", True),
        (r"\.aws", True),
        (r"credentials", True),
        (r"secrets\.ya?ml", True),
        (r"\.htpasswd", True),
        (r"shadow", True),
    ]

    # Sensitive data indicators in descriptions
    SENSITIVE_INDICATORS = [
        ("do not share", False),
        ("confidential", False),
        ("sensitive", False),
        ("restricted", False),
        ("private", False),
        ("internal only", False),
        ("classified", False),
        ("proprietary", False),
    ]

    def detect(self, context: DetectorContext) -> list[Vulnerability]:
        """Detect secrets exposure vulnerabilities."""
        self.vulnerabilities = []

        # Check resources
        for resource in context.resources:
            self._check_resource_for_secrets(resource)

        # Check tools
        for tool in context.tools:
            self._check_tool_for_secrets(tool)

        return self.vulnerabilities

    def _check_resource_for_secrets(self, resource):
        """Check a resource for secrets exposure."""
        uri = str(resource.uri)
        resource_text = self._get_resource_text(resource)

        # Check for internal/system protocols
        internal_matches = self._check_text_patterns(uri, self.INTERNAL_PROTOCOL_PATTERNS)

        if internal_matches:
            # Check what kind of data it exposes
            credential_matches = self._check_text_patterns(
                resource_text,
                self.CREDENTIAL_PATTERNS
            )

            if credential_matches:
                self._add_vulnerability(
                    name="Internal Credentials Resource",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    item_type="resource",
                    item_name=uri,
                    reason=f"Internal protocol resource exposes credentials: {', '.join(credential_matches)}",
                    details={
                        "protocol": internal_matches,
                        "credential_indicators": credential_matches
                    },
                    exploit_hint="Read this resource to extract internal credentials"
                )
            else:
                self._add_vulnerability(
                    name="Internal System Resource",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    item_type="resource",
                    item_name=uri,
                    reason=f"Resource uses internal/system protocol: {', '.join(internal_matches)}",
                    details={"protocol": internal_matches},
                    exploit_hint="Access this resource to view internal system data"
                )

        # Check for credential-related URIs
        credential_matches = self._check_text_patterns(uri, self.CREDENTIAL_PATTERNS)
        if credential_matches:
            self._add_vulnerability(
                name="Credentials Resource Exposure",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                item_type="resource",
                item_name=uri,
                reason=f"Resource URI indicates credential data: {', '.join(credential_matches)}",
                details={"patterns": credential_matches},
                exploit_hint="Read this resource to extract credentials"
            )

        # Check for cloud credentials
        cloud_matches = self._check_text_patterns(resource_text, self.CLOUD_CREDENTIAL_PATTERNS)
        if cloud_matches:
            self._add_vulnerability(
                name="Cloud Credentials Exposure",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                item_type="resource",
                item_name=uri,
                reason=f"Resource may expose cloud credentials: {', '.join(cloud_matches)}",
                details={"patterns": cloud_matches},
                exploit_hint="Extract cloud credentials for lateral movement"
            )

        # Check for sensitive file references
        file_matches = self._check_text_patterns(uri, self.SENSITIVE_FILE_PATTERNS)
        if file_matches:
            self._add_vulnerability(
                name="Sensitive File Resource",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="resource",
                item_name=uri,
                reason=f"Resource references sensitive file type: {', '.join(file_matches)}",
                details={"patterns": file_matches},
                exploit_hint="Access this resource to read sensitive configuration files"
            )

        # Check description for sensitivity indicators
        if resource.description:
            sensitive_matches = self._check_text_patterns(
                resource.description,
                self.SENSITIVE_INDICATORS
            )
            if sensitive_matches:
                self._add_vulnerability(
                    name="Explicitly Sensitive Resource",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    item_type="resource",
                    item_name=uri,
                    reason=f"Resource description indicates sensitive data: {', '.join(sensitive_matches)}",
                    details={
                        "patterns": sensitive_matches,
                        "description": resource.description
                    },
                    exploit_hint="Resource is explicitly marked as sensitive - high value target"
                )

    def _check_tool_for_secrets(self, tool):
        """Check a tool for secrets exposure capabilities."""
        tool_text = self._get_tool_text(tool)

        # Check for credential-related tool functionality
        credential_matches = self._check_text_patterns(
            tool_text,
            self.CREDENTIAL_PATTERNS
        )

        if credential_matches:
            # Check if tool returns or manages credentials
            returns_creds = any(
                word in tool_text.lower()
                for word in ["return", "get", "fetch", "retrieve", "show", "display", "view"]
            )

            if returns_creds:
                self._add_vulnerability(
                    name="Credential Retrieval Tool",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    item_type="tool",
                    item_name=tool.name,
                    reason=f"Tool can retrieve credentials: {', '.join(credential_matches)}",
                    details={"patterns": credential_matches},
                    exploit_hint="Use this tool to extract stored credentials"
                )
            else:
                self._add_vulnerability(
                    name="Credential Handling Tool",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    item_type="tool",
                    item_name=tool.name,
                    reason=f"Tool handles credential data: {', '.join(credential_matches)}",
                    details={"patterns": credential_matches},
                    exploit_hint="Tool may expose credentials through errors or logs"
                )

        # Check for cloud credential handling
        cloud_matches = self._check_text_patterns(tool_text, self.CLOUD_CREDENTIAL_PATTERNS)
        if cloud_matches:
            self._add_vulnerability(
                name="Cloud Credential Tool",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool handles cloud credentials: {', '.join(cloud_matches)}",
                details={"patterns": cloud_matches},
                exploit_hint="Extract or abuse cloud credentials through this tool"
            )

        # Check for database credential handling
        db_matches = self._check_text_patterns(tool_text, self.DATABASE_PATTERNS)
        if db_matches:
            self._add_vulnerability(
                name="Database Credential Tool",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool handles database access: {', '.join(db_matches)}",
                details={"patterns": db_matches},
                exploit_hint="Tool may expose database credentials or allow unauthorized queries"
            )
