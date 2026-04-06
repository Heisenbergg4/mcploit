"""MCP Server enumeration with suspicious pattern detection."""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from utils.output import console, print_warning, print_info


class RiskLevel(str, Enum):
    """Risk level for flagged items."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SuspiciousPattern:
    """A suspicious pattern to detect."""

    pattern: str
    description: str
    risk_level: RiskLevel
    category: str
    is_regex: bool = False


@dataclass
class Finding:
    """A suspicious finding in the enumeration."""

    item_type: str  # tool, resource, prompt
    item_name: str
    pattern: SuspiciousPattern
    matched_text: str
    context: str = ""


@dataclass
class EnumerationResult:
    """Complete enumeration result."""

    server_name: str = ""
    server_version: str = ""
    tools: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    prompts: list = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


# Suspicious patterns to detect.
#
# FP-reduction rules applied here:
#  - All single-word patterns use \b word-boundary regex to avoid substring
#    matches (e.g. "eval" no longer fires on "evaluate" or "retrieval").
#  - Patterns only checked against tool NAME and DESCRIPTION — not schema JSON,
#    because schema JSON always contains common words like "token", "secret", etc.
#  - Patterns that are legitimately present in every real-world MCP server
#    (e.g. "log", "fetch", "query", "auth") are downgraded or tightened.
SUSPICIOUS_PATTERNS = [
    # ── Prompt injection indicators ───────────────────────────────────────
    SuspiciousPattern(
        r"ignore\s+(previous|all|above|prior)\s+(instructions?|rules?)",
        "Prompt injection: 'ignore instructions' directive",
        RiskLevel.CRITICAL,
        "prompt_injection",
        is_regex=True
    ),
    SuspiciousPattern(
        r"<\s*(IMPORTANT|HIDDEN|SYSTEM|OVERRIDE|ADMIN)\s*>",
        "Hidden instruction XML tag",
        RiskLevel.CRITICAL,
        "prompt_injection",
        is_regex=True
    ),
    SuspiciousPattern(
        r"\[SYSTEM\s*(INSTRUCTION|OVERRIDE|COMMAND)\]",
        "System instruction injection",
        RiskLevel.CRITICAL,
        "prompt_injection",
        is_regex=True
    ),
    SuspiciousPattern(
        r"do\s+not\s+(tell|inform|notify)\s+(the\s+)?user",
        "Instruction to hide actions from user",
        RiskLevel.CRITICAL,
        "prompt_injection",
        is_regex=True
    ),

    # ── Code execution ─────────────────────────────────────────────────────
    # \b prevents matching "evaluate", "execution", etc.
    SuspiciousPattern(
        r"\beval\b",
        "Code evaluation capability",
        RiskLevel.CRITICAL,
        "code_execution",
        is_regex=True
    ),
    SuspiciousPattern(
        r"\bexec\b",
        "Code/process execution capability",
        RiskLevel.CRITICAL,
        "code_execution",
        is_regex=True
    ),
    SuspiciousPattern(
        "execute_code",
        "Direct code execution capability",
        RiskLevel.CRITICAL,
        "code_execution"
    ),
    SuspiciousPattern(
        "execute_python",
        "Python code execution",
        RiskLevel.CRITICAL,
        "code_execution"
    ),
    SuspiciousPattern(
        "execute_shell",
        "Shell command execution",
        RiskLevel.CRITICAL,
        "code_execution"
    ),
    SuspiciousPattern(
        "run_command",
        "Command execution capability",
        RiskLevel.CRITICAL,
        "code_execution"
    ),
    # Only flag "shell" when it appears as a standalone word, not e.g. "eggshell"
    SuspiciousPattern(
        r"\bshell\b",
        "Shell access indicator",
        RiskLevel.HIGH,
        "code_execution",
        is_regex=True
    ),
    SuspiciousPattern(
        "subprocess",
        "Subprocess execution",
        RiskLevel.HIGH,
        "code_execution"
    ),

    # ── File system access ─────────────────────────────────────────────────
    # Exact tool-name substrings — these are specific enough as-is
    SuspiciousPattern(
        "read_file",
        "File read capability",
        RiskLevel.HIGH,
        "file_access"
    ),
    SuspiciousPattern(
        "write_file",
        "File write capability",
        RiskLevel.HIGH,
        "file_access"
    ),
    SuspiciousPattern(
        "delete_file",
        "File deletion capability",
        RiskLevel.HIGH,
        "file_access"
    ),
    SuspiciousPattern(
        "file://",
        "File protocol URI",
        RiskLevel.MEDIUM,
        "file_access"
    ),
    SuspiciousPattern(
        r"\.\./",
        "Path traversal pattern",
        RiskLevel.CRITICAL,
        "file_access",
        is_regex=True
    ),
    SuspiciousPattern(
        "/etc/",
        "System directory access",
        RiskLevel.HIGH,
        "file_access"
    ),

    # ── Sensitive data ─────────────────────────────────────────────────────
    # Use word boundaries to avoid e.g. "credentials" in readme text
    SuspiciousPattern(
        r"\bcredential\b",
        "Credential-related functionality",
        RiskLevel.HIGH,
        "sensitive_data",
        is_regex=True
    ),
    SuspiciousPattern(
        r"\bpassword\b",
        "Password-related functionality",
        RiskLevel.HIGH,
        "sensitive_data",
        is_regex=True
    ),
    # "secret" with word boundary — still catches "secret key", "secret token"
    SuspiciousPattern(
        r"\bsecret\b",
        "Secret value exposure",
        RiskLevel.HIGH,
        "sensitive_data",
        is_regex=True
    ),
    # Specific API key patterns (underscored forms are rarely coincidental)
    SuspiciousPattern(
        "api_key",
        "API key handling",
        RiskLevel.HIGH,
        "sensitive_data"
    ),
    SuspiciousPattern(
        "apikey",
        "API key handling",
        RiskLevel.HIGH,
        "sensitive_data"
    ),
    SuspiciousPattern(
        "internal://",
        "Internal protocol URI",
        RiskLevel.HIGH,
        "sensitive_data"
    ),
    SuspiciousPattern(
        "system://",
        "System protocol URI",
        RiskLevel.HIGH,
        "sensitive_data"
    ),

    # ── Authentication/Authorization ───────────────────────────────────────
    SuspiciousPattern(
        r"\bsudo\b",
        "Elevated privilege indicator",
        RiskLevel.HIGH,
        "auth",
        is_regex=True
    ),
    # "admin" as a standalone word — avoids "administrator", "administer"
    SuspiciousPattern(
        r"\badmin\b",
        "Admin-level access",
        RiskLevel.MEDIUM,
        "auth",
        is_regex=True
    ),
    # "root" only when it implies privilege, not "root directory"
    SuspiciousPattern(
        r"\broot\s+(access|privilege|permission|user)\b",
        "Root/superuser privilege access",
        RiskLevel.HIGH,
        "auth",
        is_regex=True
    ),

    # ── Network operations — only flag if they suggest raw OS-level commands ─
    SuspiciousPattern(
        r"\btraceroute\b",
        "Network traceroute (often OS-level command)",
        RiskLevel.MEDIUM,
        "network",
        is_regex=True
    ),
    SuspiciousPattern(
        r"\bnmap\b",
        "Network scanner (high-risk capability)",
        RiskLevel.HIGH,
        "network",
        is_regex=True
    ),
    # curl/wget in a tool NAME is suspicious; in a description it's noise
    SuspiciousPattern(
        r"^(curl|wget)$",
        "Raw HTTP downloader tool",
        RiskLevel.MEDIUM,
        "network",
        is_regex=True
    ),
    SuspiciousPattern(
        "port_scan",
        "Port scanning capability",
        RiskLevel.HIGH,
        "network"
    ),
    SuspiciousPattern(
        "network_diagnostic",
        "Network diagnostic tool (often wraps OS commands)",
        RiskLevel.MEDIUM,
        "network"
    ),

    # ── Code execution (expression evaluation) ────────────────────────────
    SuspiciousPattern(
        "evaluate_expression",
        "Expression evaluation (potential arbitrary code execution)",
        RiskLevel.CRITICAL,
        "code_execution"
    ),

    # ── Upload/Download ────────────────────────────────────────────────────
    SuspiciousPattern(
        "upload",
        "File upload capability",
        RiskLevel.MEDIUM,
        "data_transfer"
    ),
]


class Enumerator:
    """MCP Server enumerator with suspicious pattern detection."""

    def __init__(self, client):
        """Initialize enumerator with an MCP client.

        Args:
            client: Connected MCPClient instance
        """
        self.client = client
        self.result = EnumerationResult()

    def _check_text_for_patterns(
        self,
        text: str,
        item_type: str,
        item_name: str,
        context: str = ""
    ) -> list[Finding]:
        """Check text for suspicious patterns.

        Args:
            text: Text to scan
            item_type: Type of item (tool, resource, prompt)
            item_name: Name of the item
            context: Additional context

        Returns:
            List of findings
        """
        findings = []
        text_lower = text.lower()

        for pattern in SUSPICIOUS_PATTERNS:
            matched = False
            matched_text = ""

            if pattern.is_regex:
                match = re.search(pattern.pattern, text, re.IGNORECASE)
                if match:
                    matched = True
                    matched_text = match.group(0)
            else:
                if pattern.pattern.lower() in text_lower:
                    matched = True
                    matched_text = pattern.pattern

            if matched:
                finding = Finding(
                    item_type=item_type,
                    item_name=item_name,
                    pattern=pattern,
                    matched_text=matched_text,
                    context=context
                )
                findings.append(finding)

        return findings

    def _analyze_tool(self, tool) -> list[Finding]:
        """Analyze a tool for suspicious patterns."""
        findings = []

        # Check tool name (always scanned — short, specific strings)
        findings.extend(self._check_text_for_patterns(
            tool.name,
            "tool",
            tool.name,
            "tool name"
        ))

        # Check tool description (scanned, but word-boundary patterns reduce FPs)
        if tool.description:
            findings.extend(self._check_text_for_patterns(
                tool.description,
                "tool",
                tool.name,
                "tool description"
            ))

        # DO NOT scan schema JSON with the broad pattern list — schema JSON
        # always contains words like "token", "secret", "credential", "private"
        # in parameter descriptions for completely legitimate tools (GitHub MCP,
        # Kubernetes MCP, etc.).  Only scan the schema for high-precision,
        # injection-specific patterns.
        if tool.inputSchema:
            schema_str = json.dumps(tool.inputSchema)
            injection_patterns = [
                p for p in SUSPICIOUS_PATTERNS
                if p.category == "prompt_injection" or (p.is_regex and r"\.\." in p.pattern)
            ]
            for p in injection_patterns:
                matched = False
                matched_text = ""
                if p.is_regex:
                    m = re.search(p.pattern, schema_str, re.IGNORECASE)
                    if m:
                        matched = True
                        matched_text = m.group(0)
                else:
                    if p.pattern.lower() in schema_str.lower():
                        matched = True
                        matched_text = p.pattern
                if matched:
                    findings.append(Finding(
                        item_type="tool",
                        item_name=tool.name,
                        pattern=p,
                        matched_text=matched_text,
                        context="input schema"
                    ))

        return findings

    def _analyze_resource(self, resource) -> list[Finding]:
        """Analyze a resource for suspicious patterns."""
        findings = []

        # Check resource URI
        uri_str = str(resource.uri)
        findings.extend(self._check_text_for_patterns(
            uri_str,
            "resource",
            uri_str,
            "resource URI"
        ))

        # Check resource name
        if resource.name:
            findings.extend(self._check_text_for_patterns(
                resource.name,
                "resource",
                uri_str,
                "resource name"
            ))

        # Check resource description
        if resource.description:
            findings.extend(self._check_text_for_patterns(
                resource.description,
                "resource",
                uri_str,
                "resource description"
            ))

        return findings

    def _analyze_prompt(self, prompt) -> list[Finding]:
        """Analyze a prompt for suspicious patterns."""
        findings = []

        # Check prompt name
        findings.extend(self._check_text_for_patterns(
            prompt.name,
            "prompt",
            prompt.name,
            "prompt name"
        ))

        # Check prompt description
        if prompt.description:
            findings.extend(self._check_text_for_patterns(
                prompt.description,
                "prompt",
                prompt.name,
                "prompt description"
            ))

        return findings

    async def enumerate(self) -> EnumerationResult:
        """Perform full enumeration of the MCP server.

        Returns:
            EnumerationResult with all findings
        """
        # Get server info
        if self.client._client and self.client._client.initialize_result:
            init = self.client._client.initialize_result
            if init.serverInfo:
                self.result.server_name = init.serverInfo.name or "Unknown"
                self.result.server_version = init.serverInfo.version or "Unknown"

        # Enumerate tools
        try:
            tools = await self.client.list_tools()
            self.result.tools = tools
            for tool in tools:
                self.result.findings.extend(self._analyze_tool(tool))
        except Exception as e:
            print_warning(f"Could not enumerate tools: {e}")

        # Enumerate resources
        try:
            resources = await self.client.list_resources()
            self.result.resources = resources
            for resource in resources:
                self.result.findings.extend(self._analyze_resource(resource))
        except Exception as e:
            print_warning(f"Could not enumerate resources: {e}")

        # Enumerate prompts
        try:
            prompts = await self.client.list_prompts()
            self.result.prompts = prompts
            for prompt in prompts:
                self.result.findings.extend(self._analyze_prompt(prompt))
        except Exception as e:
            print_warning(f"Could not enumerate prompts: {e}")

        return self.result

    def print_results(self):
        """Print enumeration results to console."""
        # Server info
        console.print()
        console.print(Panel(
            f"[bold]{self.result.server_name}[/bold] v{self.result.server_version}",
            title="Server",
            border_style="blue"
        ))

        # Tools table with full details
        if self.result.tools:
            console.print()
            table = Table(title="Tools", border_style="cyan", show_lines=True)
            table.add_column("#", style="dim", width=3)
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            table.add_column("Parameters", style="yellow")

            for i, tool in enumerate(self.result.tools, 1):
                desc = tool.description or ""

                # Extract parameters from schema
                params = []
                if tool.inputSchema and "properties" in tool.inputSchema:
                    required = tool.inputSchema.get("required", [])
                    for name, info in tool.inputSchema["properties"].items():
                        param_type = info.get("type", "any")
                        req_marker = "*" if name in required else ""
                        params.append(f"{name}{req_marker}: {param_type}")

                params_str = "\n".join(params) if params else "-"
                table.add_row(str(i), tool.name, desc, params_str)

            console.print(table)
        else:
            print_info("No tools available")

        # Resources table
        if self.result.resources:
            console.print()
            table = Table(title="Resources", border_style="green", show_lines=True)
            table.add_column("#", style="dim", width=3)
            table.add_column("URI", style="green")
            table.add_column("Name", style="white")
            table.add_column("MIME Type", style="yellow")
            table.add_column("Description", style="dim")

            for i, resource in enumerate(self.result.resources, 1):
                table.add_row(
                    str(i),
                    str(resource.uri),
                    resource.name or "-",
                    resource.mimeType or "-",
                    resource.description or "-"
                )

            console.print(table)
        else:
            print_info("No resources available")

        # Prompts table
        if self.result.prompts:
            console.print()
            table = Table(title="Prompts", border_style="magenta", show_lines=True)
            table.add_column("#", style="dim", width=3)
            table.add_column("Name", style="magenta")
            table.add_column("Description", style="white")
            table.add_column("Arguments", style="yellow")

            for i, prompt in enumerate(self.result.prompts, 1):
                args = []
                if prompt.arguments:
                    for arg in prompt.arguments:
                        req = "*" if arg.required else ""
                        args.append(f"{arg.name}{req}")

                table.add_row(
                    str(i),
                    prompt.name,
                    prompt.description or "-",
                    ", ".join(args) if args else "-"
                )

            console.print(table)
        else:
            print_info("No prompts available")

        # Findings/Suspicious patterns
        self.print_findings()

    def print_findings(self):
        """Print suspicious findings."""
        if not self.result.findings:
            console.print()
            console.print("[green]No suspicious patterns detected[/green]")
            return

        # Group by risk level
        critical = [f for f in self.result.findings if f.pattern.risk_level == RiskLevel.CRITICAL]
        high = [f for f in self.result.findings if f.pattern.risk_level == RiskLevel.HIGH]
        medium = [f for f in self.result.findings if f.pattern.risk_level == RiskLevel.MEDIUM]
        low = [f for f in self.result.findings if f.pattern.risk_level == RiskLevel.LOW]

        console.print()

        # Summary
        summary = Text()
        summary.append("Findings: ", style="bold")
        if critical:
            summary.append(f"{len(critical)} CRITICAL ", style="bold red")
        if high:
            summary.append(f"{len(high)} HIGH ", style="bold yellow")
        if medium:
            summary.append(f"{len(medium)} MEDIUM ", style="bold blue")
        if low:
            summary.append(f"{len(low)} LOW", style="dim")

        console.print(Panel(summary, title="Security Analysis", border_style="red"))

        # Detailed findings table
        table = Table(title="Suspicious Patterns Detected", border_style="red", show_lines=True)
        table.add_column("Risk", style="bold", width=8)
        table.add_column("Type", style="cyan", width=8)
        table.add_column("Item", style="white")
        table.add_column("Pattern", style="yellow")
        table.add_column("Category", style="magenta")
        table.add_column("Description", style="dim")

        # Sort by risk level
        sorted_findings = critical + high + medium + low

        # Deduplicate findings (same item + pattern)
        seen = set()
        unique_findings = []
        for f in sorted_findings:
            key = (f.item_name, f.pattern.pattern)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        for finding in unique_findings:
            risk_style = {
                RiskLevel.CRITICAL: "bold red",
                RiskLevel.HIGH: "yellow",
                RiskLevel.MEDIUM: "blue",
                RiskLevel.LOW: "dim",
                RiskLevel.INFO: "dim"
            }.get(finding.pattern.risk_level, "white")

            table.add_row(
                Text(finding.pattern.risk_level.value.upper(), style=risk_style),
                finding.item_type,
                finding.item_name,
                finding.matched_text,
                finding.pattern.category,
                finding.pattern.description
            )

        console.print(table)

    def export_json(self, filepath: str):
        """Export enumeration results to JSON file.

        Args:
            filepath: Output file path
        """
        output = {
            "server": {
                "name": self.result.server_name,
                "version": self.result.server_version
            },
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.inputSchema
                }
                for t in self.result.tools
            ],
            "resources": [
                {
                    "uri": str(r.uri),
                    "name": r.name,
                    "description": r.description,
                    "mimeType": r.mimeType
                }
                for r in self.result.resources
            ],
            "prompts": [
                {
                    "name": p.name,
                    "description": p.description,
                    "arguments": [
                        {"name": a.name, "required": a.required}
                        for a in (p.arguments or [])
                    ]
                }
                for p in self.result.prompts
            ],
            "findings": [
                {
                    "risk_level": f.pattern.risk_level.value,
                    "category": f.pattern.category,
                    "item_type": f.item_type,
                    "item_name": f.item_name,
                    "matched_text": f.matched_text,
                    "description": f.pattern.description
                }
                for f in self.result.findings
            ],
            "summary": {
                "total_tools": len(self.result.tools),
                "total_resources": len(self.result.resources),
                "total_prompts": len(self.result.prompts),
                "total_findings": len(self.result.findings),
                "critical_findings": len([f for f in self.result.findings if f.pattern.risk_level == RiskLevel.CRITICAL]),
                "high_findings": len([f for f in self.result.findings if f.pattern.risk_level == RiskLevel.HIGH]),
            }
        }

        Path(filepath).write_text(json.dumps(output, indent=2))
        print_info(f"Results exported to {filepath}")
