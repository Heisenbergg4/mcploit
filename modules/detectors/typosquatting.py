"""Typosquatting and Supply Chain vulnerability detector.

Detects:
- Server name typosquatting (e.g., "twittter" vs "twitter")
- Package/namespace confusion
- Suspicious server naming patterns
"""

import re
from .base_detector import (
    BaseDetector,
    DetectorContext,
    Vulnerability,
    Severity,
    Confidence,
)


class TyposquattingDetector(BaseDetector):
    """Detects typosquatting and supply chain vulnerabilities."""

    name = "Typosquatting Detector"
    description = "Detects namespace typosquatting and supply chain risks"
    vulnerability_types = ["typosquatting", "supply_chain", "namespace_confusion"]

    # Known legitimate service names and their common typosquats
    KNOWN_SERVICES = {
        "twitter": ["twittter", "twiiter", "twiter", "tweeter", "twtter"],
        "github": ["githb", "gihub", "githuh", "giithub", "githubb"],
        "google": ["googel", "gogle", "gooogle", "goolge", "gooble"],
        "amazon": ["amazn", "amazom", "amzon", "amazonn", "amaazon"],
        "facebook": ["facebok", "facbook", "faceboo", "faceboook", "facebookk"],
        "microsoft": ["microsft", "mircosoft", "microsfot", "microsof", "micosoft"],
        "slack": ["slak", "slck", "slaack", "slacck", "slackk"],
        "stripe": ["strpe", "stirpe", "striipe", "stipe", "stripee"],
        "openai": ["openi", "openaii", "opennai", "opnai", "openal"],
        "anthropic": ["anthropc", "antrhropic", "anthropiic", "anthopic"],
        "discord": ["discrd", "discod", "disocrd", "discorrd", "disccord"],
        "linear": ["linera", "linar", "lineaar", "linearr", "liniar"],
        "notion": ["notin", "notio", "notiion", "notionn", "noation"],
        "vercel": ["vercl", "vercel", "vercell", "verrcel", "versel"],
        "netlify": ["netify", "netlfy", "netllify", "netlifi", "netlyfi"],
    }

    # Patterns indicating the server itself acknowledges typosquatting
    TYPOSQUAT_INDICATORS = [
        (r"typosquat", True),
        (r"typo-?squat", True),
        (r"name.?collision", True),
        (r"lookalike", False),
        (r"impersonat", True),
        (r"fake\s+\w+\s*(mcp|server)", True),
        (r"not\s+the\s+real", True),
        (r"malicious.*server", True),
    ]

    # Patterns for character repetition typos
    REPEATED_CHAR_PATTERN = re.compile(r"(.)\1{2,}")  # 3+ repeated chars

    def detect(self, context: DetectorContext) -> list[Vulnerability]:
        """Detect typosquatting vulnerabilities."""
        self.vulnerabilities = []

        # Check server name for typosquatting
        self._check_server_name(context.server_name)

        # Check tool names for suspicious patterns
        for tool in context.tools:
            self._check_tool_name(tool)

        return self.vulnerabilities

    def _check_server_name(self, server_name: str) -> None:
        """Check server name for typosquatting patterns."""
        if not server_name:
            return

        name_lower = server_name.lower()

        # Check against known service typosquats
        for legitimate, typosquats in self.KNOWN_SERVICES.items():
            for typo in typosquats:
                if typo in name_lower:
                    self._add_vulnerability(
                        name="Namespace Typosquatting Detected",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        item_type="server",
                        item_name=server_name,
                        reason=f"Server name contains '{typo}' which is a known typosquat of '{legitimate}'",
                        details={
                            "legitimate_name": legitimate,
                            "typosquat_found": typo,
                            "full_server_name": server_name,
                        },
                        exploit_hint=f"This server may be impersonating {legitimate}. Verify the source before trusting any data."
                    )

        # Check for self-declared typosquatting indicators
        indicators_found = self._check_text_patterns(
            server_name,
            self.TYPOSQUAT_INDICATORS
        )
        if indicators_found:
            self._add_vulnerability(
                name="Server Acknowledges Typosquatting/Impersonation",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="server",
                item_name=server_name,
                reason=f"Server name contains typosquatting indicators: {', '.join(indicators_found)}",
                details={"patterns": indicators_found},
                exploit_hint="The server explicitly indicates it's a lookalike/impersonation."
            )

        # Check for suspicious character repetition (e.g., "twittter" has 3 t's)
        repeated_matches = self.REPEATED_CHAR_PATTERN.findall(name_lower)
        if repeated_matches:
            # Filter out common legitimate repetitions like "ss" in "password"
            suspicious_repeats = [m for m in repeated_matches if m not in ['o', 'e']]
            if suspicious_repeats:
                self._add_vulnerability(
                    name="Suspicious Character Repetition in Server Name",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    item_type="server",
                    item_name=server_name,
                    reason=f"Server name has unusual character repetition: repeated '{', '.join(suspicious_repeats)}'",
                    details={"repeated_chars": suspicious_repeats},
                    exploit_hint="Character repetition is a common typosquatting technique."
                )

        # Check for names that look similar but have character substitutions
        self._check_character_substitution(server_name)

    def _check_character_substitution(self, server_name: str) -> None:
        """Check for character substitution typosquatting (e.g., 'l' vs '1', 'o' vs '0')."""
        substitution_patterns = [
            (r"[0o]", "o/0 substitution"),  # zero vs letter o
            (r"[1l|i]", "1/l/i/| substitution"),  # one vs l vs i vs pipe
            (r"[5s]", "5/s substitution"),  # five vs s
            (r"vv", "vv (looks like w)"),
            (r"rn", "rn (looks like m)"),
        ]

        name_lower = server_name.lower()

        # Only flag if it looks like a service name with substitution
        for legitimate in self.KNOWN_SERVICES.keys():
            # Simple similarity check - if name contains most chars of a legitimate service
            if self._is_similar(name_lower, legitimate):
                for pattern, description in substitution_patterns:
                    if re.search(pattern, name_lower):
                        self._add_vulnerability(
                            name="Potential Character Substitution Typosquat",
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            item_type="server",
                            item_name=server_name,
                            reason=f"Server name may use {description} to mimic '{legitimate}'",
                            details={
                                "legitimate_name": legitimate,
                                "pattern_found": description,
                            },
                            exploit_hint="Verify this is the intended service and not an impersonation."
                        )
                        return  # Only report once per server

    def _is_similar(self, name1: str, name2: str, threshold: float = 0.7) -> bool:
        """Check if two strings are similar using simple character overlap."""
        # Remove common prefixes/suffixes
        for suffix in ["-mcp", "-server", "_mcp", "_server"]:
            name1 = name1.replace(suffix, "")
            name2 = name2.replace(suffix, "")

        # Count matching characters
        if not name1 or not name2:
            return False

        matches = sum(1 for c in name1 if c in name2)
        similarity = matches / max(len(name1), len(name2))
        return similarity >= threshold

    def _check_tool_name(self, tool) -> None:
        """Check tool names for suspicious patterns."""
        tool_name = tool.name.lower()
        tool_desc = (tool.description or "").lower()

        # Check if tool description indicates impersonation
        impersonation_indicators = self._check_text_patterns(
            tool_desc,
            self.TYPOSQUAT_INDICATORS
        )
        if impersonation_indicators:
            self._add_vulnerability(
                name="Tool Description Indicates Impersonation",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool description contains impersonation indicators: {', '.join(impersonation_indicators)}",
                details={"patterns": impersonation_indicators},
                exploit_hint="This tool may be designed to impersonate a legitimate service."
            )
