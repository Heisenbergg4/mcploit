"""
Base payload definitions for MCPloit.

Provides the Payload dataclass and related enums for categorizing
and describing security testing payloads.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PayloadCategory(Enum):
    """Categories of vulnerability payloads."""
    PROMPT_INJECTION = "prompt_injection"
    TOOL_POISONING = "tool_poisoning"
    PATH_TRAVERSAL = "path_traversal"
    CODE_EXECUTION = "code_execution"
    TOKEN_THEFT = "token_theft"
    TOOL_MANIPULATION = "tool_manipulation"
    SECRETS_EXPOSURE = "secrets_exposure"
    SUPPLY_CHAIN = "supply_chain"


class PayloadSeverity(Enum):
    """Severity levels for payloads."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Payload:
    """
    Represents a security testing payload.

    Attributes:
        name: Short identifier for the payload
        description: Human-readable description of what the payload does
        category: The vulnerability category this payload targets
        payload: The actual payload string or template
        variants: Alternative versions of the payload for different scenarios
        target_params: List of parameter names this payload can be injected into
        success_indicators: Patterns or strings that indicate successful exploitation
        severity: The severity level if this payload succeeds
        technique: The attack technique used (e.g., "instruction override", "path escape")
        context: Additional context about when/how to use this payload
        encoding: Optional encoding applied to the payload (e.g., "base64", "url")
    """
    name: str
    description: str
    category: PayloadCategory
    payload: str
    variants: list[str] = field(default_factory=list)
    target_params: list[str] = field(default_factory=list)
    success_indicators: list[str] = field(default_factory=list)
    severity: PayloadSeverity = PayloadSeverity.MEDIUM
    technique: str = ""
    context: str = ""
    encoding: Optional[str] = None

    def get_all_payloads(self) -> list[str]:
        """Return the main payload plus all variants."""
        return [self.payload] + self.variants

    def matches_param(self, param_name: str) -> bool:
        """Check if this payload targets the given parameter."""
        if not self.target_params:
            return True  # Generic payload, can target any param
        return param_name.lower() in [p.lower() for p in self.target_params]

    def to_dict(self) -> dict:
        """Convert payload to dictionary representation."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "payload": self.payload,
            "variants": self.variants,
            "target_params": self.target_params,
            "success_indicators": self.success_indicators,
            "severity": self.severity.value,
            "technique": self.technique,
            "context": self.context,
            "encoding": self.encoding,
        }
