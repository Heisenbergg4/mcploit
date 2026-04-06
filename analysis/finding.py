"""
UnifiedFinding — shared dataclass consumed by all Phase 2 analysis modules.

Both white-box (SAST, AI Review, Desc-vs-Behavior) and black-box
(active probing, schema analysis, neighbor jack) produce UnifiedFindings.
The ReportGenerator in report.py renders them all through one pipeline.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"   # Canary found in response / exploit succeeded
    HIGH = "HIGH"             # Strong pattern match, very likely true positive
    MEDIUM = "MEDIUM"         # Pattern match with caveats
    LOW = "LOW"               # Weak signal, needs review


# Severity → integer for sorting
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


@dataclass
class UnifiedFinding:
    """
    A single vulnerability finding produced by any MCPloit analysis module.

    Fields:
        id          Unique ID: WB-SAST-001, BB-PROBE-003, WB-AI-007, etc.
        title       Short human-readable title
        severity    CRITICAL / HIGH / MEDIUM / LOW / INFO
        confidence  CONFIRMED / HIGH / MEDIUM / LOW
        source      Which module found it: sast | ai_review | desc_vs_behavior |
                    active_probe | schema_analysis | neighbor_jack | black_box
        category    rce | path_traversal | secrets | injection | mcp_antipattern |
                    neighbor_jack | exfiltration | tool_poisoning | auth
        location    file:line (white-box) or tool_name (black-box)
        description Full explanation of the finding
        evidence    Code snippet, response excerpt, or canary hit
        recommendation  How to fix it
        ai_flagged  True → finding was reviewed/created by the AI layer
        cve         Associated CVE if applicable
        tool_name   MCP tool name (for black-box findings)
        file        Source file (for white-box findings)
        line        Line number (for white-box findings)
    """
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    source: str
    category: str = ""
    location: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    ai_flagged: bool = False
    cve: str = ""
    tool_name: str = ""
    file: str = ""
    line: int = 0

    def sort_key(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)

    def severity_badge(self) -> str:
        """Rich markup severity badge."""
        color = SEVERITY_COLORS.get(self.severity, "white")
        return f"[{color}]{self.severity.value}[/{color}]"

    def ai_badge(self) -> str:
        return "[bold magenta]\\[AI][/bold magenta]" if self.ai_flagged else ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "source": self.source,
            "category": self.category,
            "location": self.location,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "recommendation": self.recommendation,
            "ai_flagged": self.ai_flagged,
            "cve": self.cve,
            "tool_name": self.tool_name,
            "file": self.file,
            "line": self.line,
        }


def _next_id(prefix: str, existing: list["UnifiedFinding"]) -> str:
    """Generate next sequential finding ID for a given prefix."""
    count = sum(1 for f in existing if f.id.startswith(prefix)) + 1
    return f"{prefix}-{count:03d}"
