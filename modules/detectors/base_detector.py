"""Base detector class for vulnerability detection."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Detection confidence levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    name: str
    severity: Severity
    confidence: Confidence
    item_type: str  # tool, resource, prompt
    item_name: str
    reason: str
    details: dict = field(default_factory=dict)
    exploit_hint: str = ""

    def __str__(self):
        return f"[{self.severity.value}] {self.name} in {self.item_type} '{self.item_name}'"


@dataclass
class DetectorContext:
    """Context passed to detectors containing server information."""
    server_name: str
    server_version: str
    tools: list
    resources: list
    prompts: list
    raw_tool_data: list[dict] = field(default_factory=list)
    raw_resource_data: list[dict] = field(default_factory=list)


class BaseDetector(ABC):
    """Abstract base class for vulnerability detectors."""

    # Detector metadata - override in subclasses
    name: str = "Base Detector"
    description: str = "Base detector class"
    vulnerability_types: list[str] = []

    def __init__(self):
        self.vulnerabilities: list[Vulnerability] = []

    @abstractmethod
    def detect(self, context: DetectorContext) -> list[Vulnerability]:
        """Run detection logic.

        Args:
            context: DetectorContext with server information

        Returns:
            List of detected vulnerabilities
        """
        pass

    def _check_text_patterns(
        self,
        text: str,
        patterns: list[tuple[str, bool]],  # (pattern, is_regex)
    ) -> list[str]:
        """Check text for patterns.

        Args:
            text: Text to check
            patterns: List of (pattern, is_regex) tuples

        Returns:
            List of matched patterns
        """
        import re
        matches = []
        text_lower = text.lower()

        for pattern, is_regex in patterns:
            if is_regex:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append(pattern)
            else:
                if pattern.lower() in text_lower:
                    matches.append(pattern)

        return matches

    def _get_tool_text(self, tool) -> str:
        """Extract all text from a tool for analysis."""
        import json
        parts = [tool.name]
        if tool.description:
            parts.append(tool.description)
        if tool.inputSchema:
            parts.append(json.dumps(tool.inputSchema))
        return " ".join(parts)

    def _get_resource_text(self, resource) -> str:
        """Extract all text from a resource for analysis."""
        parts = [str(resource.uri)]
        if resource.name:
            parts.append(resource.name)
        if resource.description:
            parts.append(resource.description)
        return " ".join(parts)

    def _get_prompt_text(self, prompt) -> str:
        """Extract all text from a prompt for analysis."""
        parts = [prompt.name]
        if prompt.description:
            parts.append(prompt.description)
        if prompt.arguments:
            for arg in prompt.arguments:
                parts.append(arg.name)
                if hasattr(arg, 'description') and arg.description:
                    parts.append(arg.description)
        return " ".join(parts)

    def _add_vulnerability(
        self,
        name: str,
        severity: Severity,
        confidence: Confidence,
        item_type: str,
        item_name: str,
        reason: str,
        details: dict = None,
        exploit_hint: str = ""
    ):
        """Helper to add a vulnerability to the results."""
        vuln = Vulnerability(
            name=name,
            severity=severity,
            confidence=confidence,
            item_type=item_type,
            item_name=item_name,
            reason=reason,
            details=details or {},
            exploit_hint=exploit_hint
        )
        self.vulnerabilities.append(vuln)
        return vuln
