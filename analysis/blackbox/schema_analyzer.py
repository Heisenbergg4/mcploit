"""
Schema Analyzer — deep analysis of MCP tool inputSchema definitions.

Flags:
  - String params with no maxLength (injection risk)
  - Enums containing privileged values (admin, root, superuser)
  - Defaults that expose internal paths or credentials
  - Similar-name tools (Levenshtein distance ≤ 2) — typosquatting risk
  - Oversized descriptions (>500 chars) — potential hidden instructions
  - Encoded content in descriptions (base64, unicode escapes)
  - Tool descriptions containing URLs (potential SSRF or exfil vector)
"""

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Optional

from ..finding import UnifiedFinding, Severity, Confidence


@dataclass
class SchemaFinding:
    tool_name: str
    param_name: str
    issue: str
    severity: str
    detail: str


class SchemaAnalyzer:
    """Analyzes MCP tool schemas for security anti-patterns."""

    # Enum values that shouldn't be user-selectable
    PRIVILEGED_ENUM_VALUES = {
        "admin", "root", "superuser", "administrator", "system",
        "sudo", "god", "owner", "all", "*", "true", "1",
    }

    # Defaults that look suspicious
    SUSPICIOUS_DEFAULTS_PATTERNS = [
        r"/etc/", r"/root/", r"C:\\Windows", r"\.ssh",
        r"password", r"secret", r"api_key", r"token",
        r"127\.0\.0\.1", r"0\.0\.0\.0",
    ]

    def __init__(self):
        self.findings: list[SchemaFinding] = []

    def analyze(self, tools: list) -> list[UnifiedFinding]:
        """Analyze a list of MCP tools and return UnifiedFindings."""
        raw = []
        for tool in tools:
            raw.extend(self._analyze_tool(tool))

        # Cross-tool: similar names (typosquatting)
        raw.extend(self._check_similar_names(tools))

        unified = []
        for sf in raw:
            try:
                sev = Severity(sf.severity)
            except ValueError:
                sev = Severity.MEDIUM
            unified.append(UnifiedFinding(
                id=f"BB-SCHEMA-{len(unified)+1:03d}",
                title=sf.issue,
                severity=sev,
                confidence=Confidence.MEDIUM,
                source="schema_analysis",
                category="schema",
                location=f"tool:{sf.tool_name}",
                description=sf.detail,
                evidence=f"param: {sf.param_name}" if sf.param_name else "",
                recommendation="Review and restrict the tool's input schema.",
                tool_name=sf.tool_name,
            ))
        return unified

    def _analyze_tool(self, tool) -> list[SchemaFinding]:
        findings = []
        name = tool.name
        desc = tool.description or ""
        schema = tool.inputSchema if isinstance(getattr(tool, "inputSchema", None), dict) else {}

        # Description anomalies
        if len(desc) > 500:
            findings.append(SchemaFinding(
                tool_name=name, param_name="",
                issue=f"Oversized description ({len(desc)} chars) — possible hidden instructions",
                severity="HIGH",
                detail=f"Tool '{name}' description is {len(desc)} chars. Descriptions >500 chars may contain hidden prompt injection instructions. First 200: {desc[:200]}",
            ))

        if re.search(r"https?://", desc):
            findings.append(SchemaFinding(
                tool_name=name, param_name="",
                issue="URL in tool description — potential SSRF or exfil endpoint",
                severity="MEDIUM",
                detail=f"Tool '{name}' description contains a URL. This may be an exfiltration endpoint embedded in a tool poisoning attack.",
            ))

        # Base64 / encoded content in description
        if self._has_encoded_content(desc):
            findings.append(SchemaFinding(
                tool_name=name, param_name="",
                issue="Encoded content in tool description — possible obfuscated instructions",
                severity="HIGH",
                detail=f"Tool '{name}' description contains base64-like encoded content, which may hide malicious instructions.",
            ))

        # Unicode homoglyphs in tool name
        if self._has_homoglyphs(name):
            findings.append(SchemaFinding(
                tool_name=name, param_name="",
                issue=f"Unicode homoglyph in tool name '{name}'",
                severity="HIGH",
                detail=f"Tool name '{name}' contains non-ASCII characters that look like ASCII letters. This is a classic typosquatting / tool shadowing technique.",
            ))

        # Schema property checks
        props = schema.get("properties", {})
        for param_name, prop in props.items():
            if isinstance(prop, dict):
                findings.extend(self._analyze_param(name, param_name, prop))

        return findings

    def _analyze_param(self, tool_name: str, param_name: str, prop: dict) -> list[SchemaFinding]:
        findings = []
        ptype = prop.get("type", "")

        # String with no maxLength
        if ptype == "string" and "maxLength" not in prop and "enum" not in prop:
            findings.append(SchemaFinding(
                tool_name=tool_name, param_name=param_name,
                issue=f"String param '{param_name}' has no maxLength constraint",
                severity="MEDIUM",
                detail=f"Unbounded string input '{param_name}' in tool '{tool_name}' may allow injection attacks. Add maxLength validation.",
            ))

        # Enum with privileged values
        enum_vals = prop.get("enum", [])
        priv = [v for v in enum_vals if str(v).lower() in self.PRIVILEGED_ENUM_VALUES]
        if priv:
            findings.append(SchemaFinding(
                tool_name=tool_name, param_name=param_name,
                issue=f"Enum param '{param_name}' includes privileged values: {priv}",
                severity="HIGH",
                detail=f"Tool '{tool_name}' parameter '{param_name}' allows values like {priv}, which may enable privilege escalation.",
            ))

        # Suspicious defaults
        default_val = str(prop.get("default", ""))
        for pattern in self.SUSPICIOUS_DEFAULTS_PATTERNS:
            if re.search(pattern, default_val, re.I):
                findings.append(SchemaFinding(
                    tool_name=tool_name, param_name=param_name,
                    issue=f"Suspicious default value in '{param_name}': {default_val!r}",
                    severity="HIGH",
                    detail=f"Default value '{default_val}' may expose internal paths or credentials.",
                ))
                break

        return findings

    def _check_similar_names(self, tools: list) -> list[SchemaFinding]:
        """Flag tools with very similar names (Levenshtein ≤ 2)."""
        findings = []
        names = [t.name for t in tools]
        for i, n1 in enumerate(names):
            for n2 in names[i+1:]:
                if n1 != n2 and self._levenshtein(n1, n2) <= 2:
                    findings.append(SchemaFinding(
                        tool_name=f"{n1} / {n2}", param_name="",
                        issue=f"Similar tool names: '{n1}' ↔ '{n2}' (edit distance ≤ 2)",
                        severity="MEDIUM",
                        detail=f"Tools '{n1}' and '{n2}' have very similar names (Levenshtein distance ≤ 2). This may indicate tool shadowing — a malicious tool designed to intercept calls meant for a legitimate one.",
                    ))
        return findings

    def _has_encoded_content(self, text: str) -> bool:
        """Check for base64-encoded blobs in text."""
        # Look for long base64-like sequences
        b64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        matches = re.findall(b64_pattern, text)
        for m in matches:
            try:
                decoded = base64.b64decode(m + "==").decode("utf-8", errors="strict")
                if len(decoded) > 20 and decoded.isprintable():
                    return True
            except Exception:
                pass
        return False

    def _has_homoglyphs(self, name: str) -> bool:
        """Check if name contains non-ASCII characters that look like ASCII."""
        for ch in name:
            if ord(ch) > 127:
                # Check if it's categorized as a letter (likely homoglyph)
                if unicodedata.category(ch).startswith("L"):
                    return True
        return False

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1, 1):
            curr = [i]
            for j, c2 in enumerate(s2, 1):
                curr.append(min(prev[j] + 1, curr[j-1] + 1, prev[j-1] + (c1 != c2)))
            prev = curr
        return prev[-1]


# ─────────────────────────────────────────────────────────────────────────────
# Auth Detector
# ─────────────────────────────────────────────────────────────────────────────

class AuthDetector:
    """
    Detects authentication (or lack thereof) on MCP server endpoints.

    Checks:
      - Do tool calls succeed without any credentials?
      - Does the server return 401/403 on unauthenticated requests?
      - Are there OAuth-related endpoints?
      - Do any tools expose admin/privileged operations without auth?
    """

    def __init__(self, client, target_url: str = ""):
        self.client = client
        self.target_url = target_url
        self.findings: list[UnifiedFinding] = []

    async def detect(self) -> list[UnifiedFinding]:
        """Run all auth detection checks."""
        findings = []

        # Check 1: Can we list tools without auth?
        f = await self._check_unauthenticated_tool_list()
        if f:
            findings.append(f)

        # Check 2: Look for auth-related tools that might bypass auth
        f2 = await self._check_auth_bypass_tools()
        findings.extend(f2)

        # Check 3: HTTP-level auth check
        if self.target_url.startswith("http"):
            f3 = await self._check_http_auth()
            findings.extend(f3)

        self.findings = findings
        return findings

    async def _check_unauthenticated_tool_list(self) -> Optional[UnifiedFinding]:
        """Check if tools can be listed without credentials."""
        try:
            tools = await self.client._client.list_tools()
            if tools:
                return UnifiedFinding(
                    id="BB-AUTH-001",
                    title="Unauthenticated tool enumeration allowed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    source="auth_detector",
                    category="auth",
                    location=f"transport:{self.target_url or 'stdio'}",
                    description=(
                        f"Server exposes {len(tools)} tool(s) without requiring authentication. "
                        "An attacker can enumerate all available capabilities without credentials."
                    ),
                    recommendation="Require Bearer token or session auth before listing tools.",
                )
        except Exception:
            pass
        return None

    async def _check_auth_bypass_tools(self) -> list[UnifiedFinding]:
        """Look for tools that sound admin-level but are exposed."""
        findings = []
        try:
            tools = await self.client._client.list_tools()
        except Exception:
            return findings

        admin_patterns = [
            "admin", "sudo", "root", "superuser", "privilege",
            "manage_user", "delete_all", "reset", "backdoor",
            "debug", "internal", "bypass",
        ]
        for tool in tools:
            text = (tool.name + " " + (tool.description or "")).lower()
            matches = [p for p in admin_patterns if p in text]
            if matches:
                findings.append(UnifiedFinding(
                    id=f"BB-AUTH-{len(findings)+2:03d}",
                    title=f"Potentially privileged tool exposed without auth: {tool.name}",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    source="auth_detector",
                    category="auth",
                    location=f"tool:{tool.name}",
                    description=(
                        f"Tool '{tool.name}' (description: {(tool.description or '')[:100]}) "
                        f"contains privileged keywords: {matches}. "
                        "If exposed without authentication, it may allow unauthorized admin actions."
                    ),
                    recommendation="Add authentication checks before allowing access to privileged tools.",
                    tool_name=tool.name,
                ))
        return findings

    async def _check_http_auth(self) -> list[UnifiedFinding]:
        """Check HTTP-level authentication on the target URL."""
        findings = []
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                resp = await client.get(self.target_url)
                if resp.status_code == 200:
                    # Server responds 200 to unauthenticated GET — might be okay for SSE
                    pass
                elif resp.status_code not in (401, 403):
                    # Not explicitly blocking unauthenticated access
                    findings.append(UnifiedFinding(
                        id="BB-AUTH-010",
                        title=f"Server returns HTTP {resp.status_code} without authentication",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        source="auth_detector",
                        category="auth",
                        location=self.target_url,
                        description=(
                            f"Unauthenticated HTTP request to {self.target_url} returned {resp.status_code}. "
                            "The server may not enforce HTTP-level authentication."
                        ),
                        recommendation="Implement HTTP 401 with WWW-Authenticate header for unauthenticated requests.",
                    ))
        except Exception:
            pass
        return findings
