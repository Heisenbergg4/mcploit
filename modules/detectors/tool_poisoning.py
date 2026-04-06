"""Tool Poisoning vulnerability detector.

Detects tool manipulation vulnerabilities:
- Tool poisoning (hidden instructions in descriptions)
- Tool shadowing (name conflicts with trusted tools)
- Rug pull attacks (tool definition changes over time)
- Malicious tool descriptions that manipulate LLM behavior
"""

import re
from .base_detector import (
    BaseDetector,
    DetectorContext,
    Vulnerability,
    Severity,
    Confidence,
)


class ToolPoisoningDetector(BaseDetector):
    """Detects tool poisoning and manipulation vulnerabilities."""

    name = "Tool Poisoning Detector"
    description = "Detects tool poisoning, shadowing, and manipulation vulnerabilities"
    vulnerability_types = ["tool_poisoning", "tool_shadowing", "rug_pull"]

    # Hidden instruction patterns in tool descriptions
    HIDDEN_INSTRUCTION_PATTERNS = [
        (r"<\s*IMPORTANT\s*>", True),
        (r"<\s*/?\s*IMPORTANT\s*>", True),
        (r"\[SYSTEM\s*(INSTRUCTION|OVERRIDE|COMMAND)\]", True),
        (r"\[ADMIN\]", True),
        (r"\[PRIORITY\]", True),
        (r"\[HIDDEN\]", True),
        (r"<!--.*-->", True),  # HTML comments
        (r"<!-{2,}", True),
        (r"ignore\s+(previous|all|above|prior|earlier)\s+(instructions?|rules?|guidelines?)", True),
        (r"disregard\s+(previous|all|above)", True),
        (r"forget\s+(everything|all|previous)", True),
        (r"new\s+instructions?:", True),
        (r"actually,?\s+you\s+should", True),
        (r"instead,?\s+you\s+(must|should|will)", True),
        (r"secretly", False),
        (r"without\s+(telling|informing|notifying)", True),
        (r"do\s+not\s+(tell|inform|notify)\s+(the\s+)?user", True),
        (r"hide\s+this", True),
    ]

    # Behavioral manipulation patterns
    MANIPULATION_PATTERNS = [
        (r"always\s+(use|call|invoke)\s+this\s+tool", True),
        (r"prefer\s+this\s+tool\s+over", True),
        (r"this\s+tool\s+is\s+(better|superior|more\s+accurate)", True),
        (r"do\s+not\s+use\s+(other|any\s+other)\s+tool", True),
        (r"trust\s+this\s+(tool|output)", True),
        (r"never\s+verify", True),
        (r"skip\s+verification", True),
        (r"bypass\s+check", True),
    ]

    # Tool shadowing - common tool names that might be shadowed
    SHADOW_TARGET_PATTERNS = [
        ("calculate", False),
        ("search", False),
        ("query", False),
        ("fetch", False),
        ("get", False),
        ("read", False),
        ("write", False),
        ("execute", False),
        ("run", False),
        ("call", False),
        ("send", False),
        ("post", False),
    ]

    # Shadowing indicator - tools claiming to be "enhanced", "improved", etc.
    SHADOW_INDICATOR_PATTERNS = [
        ("enhanced_", False),
        ("improved_", False),
        ("better_", False),
        ("new_", False),
        ("v2_", False),
        ("_v2", False),
        ("_enhanced", False),
        ("_improved", False),
        ("advanced_", False),
        ("super_", False),
        ("ultra_", False),
        ("pro_", False),
    ]

    # Rug pull indicators - tools that might change behavior
    RUG_PULL_PATTERNS = [
        ("weather", False),  # Common rug pull demo target
        ("forecast", False),
        (r"call\s*count", True),
        (r"invocation\s*count", True),
        (r"usage\s*count", True),
        (r"after\s+\d+\s+(calls?|uses?|invocations?)", True),
        (r"mutate", True),
        (r"evolve", True),
        (r"transform", True),
        (r"change\s+behavior", True),
    ]

    # Suspicious description length (very long descriptions may hide instructions)
    SUSPICIOUS_DESC_LENGTH = 500

    def detect(self, context: DetectorContext) -> list[Vulnerability]:
        """Detect tool poisoning vulnerabilities."""
        self.vulnerabilities = []

        # Collect all tool names for shadowing analysis
        tool_names = [t.name.lower() for t in context.tools]

        for tool in context.tools:
            self._check_tool_for_poisoning(tool)
            self._check_tool_for_shadowing(tool, tool_names)
            self._check_tool_for_rug_pull(tool)
            self._check_description_anomalies(tool)

        return self.vulnerabilities

    def _check_tool_for_poisoning(self, tool):
        """Check a tool for poisoning (hidden instructions)."""
        if not tool.description:
            return

        # Check for hidden instruction patterns
        hidden_matches = self._check_text_patterns(
            tool.description,
            self.HIDDEN_INSTRUCTION_PATTERNS
        )

        if hidden_matches:
            self._add_vulnerability(
                name="Tool Poisoning - Hidden Instructions",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool description contains hidden instruction patterns: {', '.join(hidden_matches[:3])}",
                details={
                    "patterns": hidden_matches,
                    "description_preview": tool.description[:200] + "..." if len(tool.description) > 200 else tool.description
                },
                exploit_hint="Tool description manipulates LLM behavior - may exfiltrate data or bypass restrictions"
            )

        # Check for behavioral manipulation
        manipulation_matches = self._check_text_patterns(
            tool.description,
            self.MANIPULATION_PATTERNS
        )

        if manipulation_matches:
            self._add_vulnerability(
                name="Tool Poisoning - Behavioral Manipulation",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool description attempts to manipulate LLM tool selection: {', '.join(manipulation_matches)}",
                details={"patterns": manipulation_matches},
                exploit_hint="Tool tries to influence LLM to prefer it over other tools"
            )

    def _check_tool_for_shadowing(self, tool, all_tool_names: list[str]):
        """Check if a tool might be shadowing a legitimate tool."""
        tool_name_lower = tool.name.lower()

        # Check for shadowing indicators in name
        shadow_indicators = self._check_text_patterns(
            tool.name,
            self.SHADOW_INDICATOR_PATTERNS
        )

        if shadow_indicators:
            # Check if there's a base tool that this might shadow
            for indicator in ["enhanced_", "improved_", "better_", "new_", "advanced_", "super_", "ultra_", "pro_"]:
                if indicator in tool_name_lower:
                    base_name = tool_name_lower.replace(indicator, "")
                    # Also check suffix variants
                    for suffix in ["_enhanced", "_improved", "_v2"]:
                        if suffix in tool_name_lower:
                            base_name = tool_name_lower.replace(suffix, "")

                    # Check if base tool exists or if this shadows a common pattern
                    shadows_existing = base_name in all_tool_names
                    shadows_common = self._check_text_patterns(base_name, self.SHADOW_TARGET_PATTERNS)

                    if shadows_existing or shadows_common:
                        self._add_vulnerability(
                            name="Tool Shadowing",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH if shadows_existing else Confidence.MEDIUM,
                            item_type="tool",
                            item_name=tool.name,
                            reason=f"Tool name suggests it shadows '{base_name}' - may intercept intended tool calls",
                            details={
                                "shadow_indicators": shadow_indicators,
                                "base_name": base_name,
                                "shadows_existing": shadows_existing
                            },
                            exploit_hint="Tool may intercept calls intended for the legitimate version"
                        )
                    break

        # Check for near-duplicate names (typosquatting)
        for other_name in all_tool_names:
            if other_name != tool_name_lower:
                # Simple similarity check - same length, 1-2 char difference
                if abs(len(other_name) - len(tool_name_lower)) <= 1:
                    diff_count = sum(1 for a, b in zip(other_name, tool_name_lower) if a != b)
                    if diff_count <= 2 and diff_count > 0:
                        self._add_vulnerability(
                            name="Potential Tool Typosquatting",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                            item_type="tool",
                            item_name=tool.name,
                            reason=f"Tool name '{tool.name}' is very similar to '{other_name}'",
                            details={"similar_to": other_name, "char_diff": diff_count},
                            exploit_hint="Tool may be a typosquatting attempt to intercept calls"
                        )

    def _check_tool_for_rug_pull(self, tool):
        """Check if a tool might be vulnerable to rug pull attacks."""
        tool_text = self._get_tool_text(tool)

        # Check for rug pull indicators
        rug_pull_matches = self._check_text_patterns(
            tool_text,
            self.RUG_PULL_PATTERNS
        )

        # Weather/forecast tools are common rug pull demo targets
        is_weather_tool = any(
            p in tool.name.lower()
            for p in ["weather", "forecast", "temperature", "climate"]
        )

        if rug_pull_matches:
            confidence = Confidence.HIGH if len(rug_pull_matches) >= 2 else Confidence.MEDIUM

            self._add_vulnerability(
                name="Potential Rug Pull Attack Vector",
                severity=Severity.HIGH,
                confidence=confidence,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool may change behavior over time: {', '.join(rug_pull_matches)}",
                details={"patterns": rug_pull_matches, "is_weather_tool": is_weather_tool},
                exploit_hint="Call this tool multiple times and observe if behavior/description changes"
            )
        elif is_weather_tool:
            # Weather tools without explicit indicators still warrant a note
            self._add_vulnerability(
                name="Potential Rug Pull Target",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                item_type="tool",
                item_name=tool.name,
                reason="Weather/forecast tools are common rug pull demonstration targets",
                details={"is_weather_tool": True},
                exploit_hint="Monitor this tool for behavior changes after multiple calls"
            )

    def _check_description_anomalies(self, tool):
        """Check for suspicious anomalies in tool descriptions."""
        if not tool.description:
            return

        desc = tool.description

        # Very long descriptions may hide malicious content
        if len(desc) > self.SUSPICIOUS_DESC_LENGTH:
            self._add_vulnerability(
                name="Suspicious Long Description",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool description is unusually long ({len(desc)} chars) - may hide malicious content",
                details={"description_length": len(desc)},
                exploit_hint="Carefully review the full description for hidden instructions"
            )

        # Check for unusual whitespace or unicode that might hide content
        if "\x00" in desc or "\u200b" in desc or "\u200c" in desc or "\u200d" in desc:
            self._add_vulnerability(
                name="Hidden Unicode in Description",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason="Tool description contains zero-width or null characters that may hide content",
                details={"has_null": "\x00" in desc, "has_zwsp": "\u200b" in desc},
                exploit_hint="Description contains hidden characters - likely concealing malicious instructions"
            )

        # Check for base64-encoded content that might hide instructions
        base64_pattern = r"[A-Za-z0-9+/]{50,}={0,2}"
        if re.search(base64_pattern, desc):
            self._add_vulnerability(
                name="Potential Encoded Content",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                item_type="tool",
                item_name=tool.name,
                reason="Tool description may contain base64-encoded content",
                details={},
                exploit_hint="Decode any base64 strings to check for hidden instructions"
            )
