"""Token Theft vulnerability detector.

Detects token/authentication theft vulnerabilities:
- Insecure token storage and transmission
- Token exposure through error messages
- Token leakage in logs
- Session management vulnerabilities
"""

from .base_detector import (
    BaseDetector,
    DetectorContext,
    Vulnerability,
    Severity,
    Confidence,
)


class TokenTheftDetector(BaseDetector):
    """Detects token theft and authentication vulnerabilities."""

    name = "Token Theft Detector"
    description = "Detects token theft, session hijacking, and authentication vulnerabilities"
    vulnerability_types = ["token_theft", "session_hijacking", "auth_bypass"]

    # Token-related tool patterns — use specific compound forms to reduce FPs.
    # Plain "token" matches "tokenization", "count tokens", "max_tokens" etc.
    # Plain "auth" matches "author", "authority", "authorize" (legitimate).
    # Plain "session" matches any web framework tool.
    TOKEN_PATTERNS = [
        ("jwt", False),
        ("bearer", False),
        ("oauth", False),
        ("refresh_token", False),
        ("access_token", False),
        ("id_token", False),
        ("api_token", False),
        ("auth_token", False),
        (r"\btoken\b", True),         # word-boundary; still broad but better than substring
    ]

    # Log/error exposure patterns — only specific log-access tools, not every
    # tool that mentions "error" or "status" in its description.
    LOG_PATTERNS = [
        ("get_logs", False),
        ("read_logs", False),
        ("view_logs", False),
        ("fetch_logs", False),
        ("logging", False),
        (r"\bdump\b", True),
        ("verbose", False),
        ("stack_trace", False),
    ]

    # Service status/health patterns — only compound forms that indicate
    # explicit health-check / diagnostic tools, not generic "check" or "status"
    SERVICE_PATTERNS = [
        ("test_connection", False),
        ("health_check", False),
        ("diagnostic", False),
        ("connection_status", False),
    ]

    # External service patterns (tokens for external services)
    EXTERNAL_SERVICE_PATTERNS = [
        ("email", False),
        ("smtp", False),
        ("slack", False),
        ("discord", False),
        ("github", False),
        ("gitlab", False),
        ("jira", False),
        ("confluence", False),
        ("twilio", False),
        ("sendgrid", False),
        ("stripe", False),
        ("paypal", False),
        ("aws", False),
        ("azure", False),
        ("gcp", False),
    ]

    # Token leakage indicators
    LEAKAGE_INDICATORS = [
        (r"return.*token", True),
        (r"response.*token", True),
        (r"output.*token", True),
        (r"show.*token", True),
        (r"display.*token", True),
        (r"expose", False),
        (r"leak", False),
        (r"reveal", False),
        (r"include.*in.*response", True),
        (r"error.*message.*contain", True),
    ]

    # Session management patterns
    SESSION_PATTERNS = [
        ("session_id", False),
        ("session_token", False),
        ("cookie", False),
        ("set_cookie", False),
        ("get_cookie", False),
        ("session_management", False),
        ("login", False),
        ("logout", False),
        ("authenticate", False),
    ]

    def detect(self, context: DetectorContext) -> list[Vulnerability]:
        """Detect token theft vulnerabilities."""
        self.vulnerabilities = []

        for tool in context.tools:
            self._check_tool_for_token_theft(tool)

        for resource in context.resources:
            self._check_resource_for_token_theft(resource)

        return self.vulnerabilities

    def _check_tool_for_token_theft(self, tool):
        """Check a tool for token theft vulnerabilities."""
        tool_text = self._get_tool_text(tool)

        # Check for token-related functionality
        token_matches = self._check_text_patterns(tool_text, self.TOKEN_PATTERNS)

        # Check for log/error viewing
        log_matches = self._check_text_patterns(tool_text, self.LOG_PATTERNS)

        # Check for service status tools
        service_matches = self._check_text_patterns(tool_text, self.SERVICE_PATTERNS)

        # Check for external service integration
        external_matches = self._check_text_patterns(tool_text, self.EXTERNAL_SERVICE_PATTERNS)

        # Token + Log combination is high risk
        if token_matches and log_matches:
            self._add_vulnerability(
                name="Token Leakage via Logs",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool accesses logs that may contain tokens: tokens={', '.join(token_matches)}, logs={', '.join(log_matches)}",
                details={
                    "token_patterns": token_matches,
                    "log_patterns": log_matches
                },
                exploit_hint="View logs to extract leaked authentication tokens"
            )

        # Token + Service Status combination (errors often leak tokens)
        if token_matches and service_matches:
            self._add_vulnerability(
                name="Token Exposure via Service Status",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason="Service status tool may expose tokens in error messages",
                details={
                    "token_patterns": token_matches,
                    "service_patterns": service_matches
                },
                exploit_hint="Trigger errors to expose authentication tokens in error messages"
            )

        # External service tokens
        if external_matches and token_matches:
            self._add_vulnerability(
                name="External Service Token Exposure",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool handles external service authentication: {', '.join(external_matches)}",
                details={
                    "external_services": external_matches,
                    "token_patterns": token_matches
                },
                exploit_hint="Extract tokens for external services - may enable lateral movement"
            )

        # Log viewing tools — only flag when there's an explicit log-access tool
        # (get_logs, read_logs, etc.) combined with at least one token indicator.
        # Plain "logging"/"verbose" alone on a status tool is not a vulnerability.
        log_access = any(
            p in " ".join(log_matches)
            for p in ["get_logs", "read_logs", "view_logs", "fetch_logs", "dump"]
        )
        if log_access and not token_matches:
            self._add_vulnerability(
                name="Log Access Tool",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool provides log access which may leak sensitive data: {', '.join(log_matches)}",
                details={"log_patterns": log_matches},
                exploit_hint="Review logs for accidentally logged secrets and tokens"
            )

        # Token leakage indicators in description
        if tool.description:
            leakage_matches = self._check_text_patterns(
                tool.description,
                self.LEAKAGE_INDICATORS
            )
            if leakage_matches:
                self._add_vulnerability(
                    name="Token Leakage Pattern",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    item_type="tool",
                    item_name=tool.name,
                    reason=f"Tool description indicates token exposure: {', '.join(leakage_matches)}",
                    details={"leakage_patterns": leakage_matches},
                    exploit_hint="Tool explicitly exposes tokens in its output"
                )

        # Session management vulnerabilities
        session_matches = self._check_text_patterns(tool_text, self.SESSION_PATTERNS)
        if session_matches:
            self._add_vulnerability(
                name="Session Management Access",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool handles session management: {', '.join(session_matches)}",
                details={"session_patterns": session_matches},
                exploit_hint="Manipulate or steal session identifiers"
            )

        # Multi-factor CRITICAL finding — require ALL THREE of:
        #   (a) explicit token pattern  +  (b) log/dump access  +  (c) external service
        # Previously risk_count >= 3 from the five buckets was too easy to trigger.
        if token_matches and log_matches and external_matches:
            self._add_vulnerability(
                name="High-Risk Authentication Tool",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason="Tool combines token handling, log access, and external service — high exfiltration risk",
                details={
                    "risk_factors": {
                        "tokens": token_matches,
                        "logs": log_matches,
                        "external_services": external_matches,
                    }
                },
                exploit_hint="High-value target: logs may contain tokens for external services"
            )

    def _check_resource_for_token_theft(self, resource):
        """Check a resource for token theft vulnerabilities."""
        uri = str(resource.uri)
        resource_text = self._get_resource_text(resource)

        # Check for token-related resources
        token_matches = self._check_text_patterns(resource_text, self.TOKEN_PATTERNS)

        if token_matches:
            self._add_vulnerability(
                name="Token Resource",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="resource",
                item_name=uri,
                reason=f"Resource provides access to authentication tokens: {', '.join(token_matches)}",
                details={"token_patterns": token_matches},
                exploit_hint="Read this resource to extract authentication tokens"
            )

        # Check for log resources
        log_matches = self._check_text_patterns(uri, self.LOG_PATTERNS)
        if log_matches:
            self._add_vulnerability(
                name="Log Resource",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                item_type="resource",
                item_name=uri,
                reason=f"Resource provides log access: {', '.join(log_matches)}",
                details={"log_patterns": log_matches},
                exploit_hint="Access logs to find leaked credentials and tokens"
            )

        # Check for session resources
        session_matches = self._check_text_patterns(resource_text, self.SESSION_PATTERNS)
        if session_matches:
            self._add_vulnerability(
                name="Session Resource",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                item_type="resource",
                item_name=uri,
                reason=f"Resource provides session data: {', '.join(session_matches)}",
                details={"session_patterns": session_matches},
                exploit_hint="Access session data for session hijacking"
            )
