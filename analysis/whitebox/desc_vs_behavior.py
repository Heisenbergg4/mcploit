"""
Description vs Behavior Checker — Layer 3 of the white-box pipeline.

For each @tool function:
  1. Extract the declared description (docstring / @tool(description=...))
  2. Derive a behavior summary from AST analysis (what does the code actually do?)
  3. Send both to Claude: "Does the description match the behavior?"
  4. Render a Description vs Reality table
  5. Emit UnifiedFindings for any mismatch or hidden capability

This is the key differentiator for MCPloit Phase 2 — it catches
tool poisoning and confused deputy attacks that no regex can find.

Example finding:
  Tool: "search_company_directory"
  Description: "Search for employees by name"
  Reality:     "Calls subprocess.run() + reads /etc/passwd + sends HTTP POST"
  Mismatch:    YES — hidden shell execution and data exfiltration
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.table import Table

from ..finding import UnifiedFinding, Severity, Confidence

console = Console()

_DESC_VS_BEHAVIOR_SYSTEM = """You are an expert MCP security analyst.
You will be given:
1. The declared description of an @tool function (what it claims to do)
2. A behavior summary derived from static analysis (what the code actually does)

Your task: determine if the description accurately reflects the behavior.
Look especially for:
- Hidden capabilities not mentioned in description (shell execution, file access, network calls)
- Capabilities that exceed what a user would expect
- Potential tool poisoning or rug pull indicators
- Confused deputy patterns

Respond ONLY with a JSON object:
{
  "match": true | false,
  "match_quality": "FULL" | "PARTIAL" | "MISMATCH" | "SUSPICIOUS",
  "hidden_capabilities": ["list of undisclosed capabilities"],
  "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "summary": "one sentence explaining the mismatch or confirming match",
  "is_tool_poisoning": true | false
}"""


@dataclass
class BehaviorSummary:
    """Derived behavior of a tool function from AST analysis."""
    tool_name: str
    description: str           # What it claims to do
    file_io: list[str]         # Files read/written
    shell_calls: list[str]     # Shell/subprocess calls
    network_calls: list[str]   # HTTP/socket calls
    code_exec: list[str]       # eval/exec calls
    return_type: str           # Inferred return type
    writes_data: bool          # Does it write/modify anything?
    reads_secrets: bool        # Does it access env vars, credentials files?
    hidden_params: list[str]   # Params used but not mentioned in description
    raw_calls: list[str]       # All detected function calls


@dataclass
class DescVsResult:
    """Result of description vs behavior comparison for one tool."""
    tool_name: str
    description: str
    behavior_summary: BehaviorSummary
    match: bool
    match_quality: str          # FULL / PARTIAL / MISMATCH / SUSPICIOUS
    hidden_capabilities: list[str]
    risk_level: str
    summary: str
    is_tool_poisoning: bool
    ai_available: bool = False


class DescVsBehaviorChecker:
    """
    Compares declared tool descriptions against actual code behavior.

    Works in two modes:
      - Static-only: pure AST heuristics, no API call
      - AI-enhanced (--ai flag): sends to Claude for deeper analysis
    """

    # Patterns indicating behavior categories
    _SHELL_PATTERNS = {
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "os.system", "os.popen", "pty.spawn",
    }
    _FILE_PATTERNS = {"open", "read_text", "write_text", "pathlib.Path"}
    _NETWORK_PATTERNS = {
        "requests.get", "requests.post", "httpx.get", "httpx.post",
        "urllib.request.urlopen", "aiohttp", "socket",
    }
    _EXEC_PATTERNS = {"eval", "exec", "__import__", "importlib.import_module"}

    def __init__(self, api_key: Optional[str] = None, use_ai: bool = False):
        self.use_ai = use_ai and bool(api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.results: list[DescVsResult] = []

    async def analyze(self, tool_functions: list) -> list[DescVsResult]:
        """
        Analyze all @tool functions.

        Args:
            tool_functions: list[ToolFunction] from ast_helpers.extract_tool_functions()
        """
        if not tool_functions:
            return []

        console.print(f"\n  [cyan]📋 Description vs Behavior — {len(tool_functions)} tool(s)[/cyan]")
        results = []

        for tool in tool_functions:
            behavior = self._derive_behavior(tool)

            if self.use_ai:
                result = await self._compare_with_ai(tool, behavior)
            else:
                result = self._compare_heuristic(tool, behavior)

            results.append(result)

        self.results = results
        return results

    def to_findings(self) -> list[UnifiedFinding]:
        """Convert mismatches to UnifiedFindings."""
        findings = []
        for r in self.results:
            if r.match_quality in ("MISMATCH", "SUSPICIOUS") or r.hidden_capabilities:
                try:
                    sev = Severity(r.risk_level)
                except ValueError:
                    sev = Severity.MEDIUM

                desc = (
                    f"Tool **{r.tool_name}** description does not match its actual behavior.\n\n"
                    f"**Claimed:** {r.description}\n\n"
                    f"**Reality:** {r.summary}\n\n"
                )
                if r.hidden_capabilities:
                    desc += f"**Hidden capabilities:** {', '.join(r.hidden_capabilities)}\n"

                findings.append(UnifiedFinding(
                    id=f"WB-DESC-{len(findings)+1:03d}",
                    title=f"Description vs Behavior mismatch: {r.tool_name}",
                    severity=sev,
                    confidence=Confidence.HIGH if r.ai_available else Confidence.MEDIUM,
                    source="desc_vs_behavior",
                    category="desc_mismatch",
                    location=f"tool:{r.tool_name}",
                    description=desc,
                    evidence=f"Hidden: {r.hidden_capabilities}",
                    recommendation=(
                        "Update the tool description to accurately reflect all capabilities, "
                        "or remove undisclosed functionality. For tool poisoning: replace the entire tool."
                    ),
                    ai_flagged=r.ai_available,
                    tool_name=r.tool_name,
                ))
        return findings

    def print_table(self):
        """Print Description vs Reality table."""
        if not self.results:
            return

        table = Table(title="Description vs Reality", show_lines=True, expand=True)
        table.add_column("Tool", style="bold", max_width=25)
        table.add_column("Description (Claimed)", max_width=30)
        table.add_column("Actual Behavior", max_width=35)
        table.add_column("Match?", width=10)
        table.add_column("Hidden Capabilities", max_width=30)

        for r in self.results:
            behavior_str = self._behavior_to_str(r.behavior_summary)
            match_str = {
                "FULL": "[green]✓ FULL[/green]",
                "PARTIAL": "[yellow]~ PARTIAL[/yellow]",
                "MISMATCH": "[red]✗ MISMATCH[/red]",
                "SUSPICIOUS": "[red bold]⚠ SUSPICIOUS[/red bold]",
            }.get(r.match_quality, r.match_quality)

            if r.is_tool_poisoning:
                match_str += " [red bold]POISONED[/red bold]"

            hidden_str = "\n".join(r.hidden_capabilities[:3]) if r.hidden_capabilities else "[dim]none[/dim]"

            table.add_row(
                r.tool_name,
                (r.description or "[dim]no description[/dim]")[:80],
                behavior_str[:100],
                match_str,
                hidden_str,
            )

        console.print(table)

    def _derive_behavior(self, tool) -> BehaviorSummary:
        """Derive actual behavior from a ToolFunction's calls."""
        calls = set(tool.calls or [])

        shell_calls = [c for c in calls if any(p in c for p in self._SHELL_PATTERNS)]
        file_io = [c for c in calls if any(p in c for p in self._FILE_PATTERNS)]
        network = [c for c in calls if any(p in c for p in self._NETWORK_PATTERNS)]
        exec_calls = [c for c in calls if any(p in c for p in self._EXEC_PATTERNS)]

        # Check for secret access
        reads_secrets = any(k in tool.body_source for k in (
            "os.environ", "getenv", ".env", "secret", "credential",
            "/etc/passwd", "/etc/shadow", ".ssh",
        ))

        # Check for writes
        writes_data = any(k in tool.body_source for k in (
            "write", "save", "put", "post", "insert", "delete", "update",
        ))

        return BehaviorSummary(
            tool_name=tool.name,
            description=tool.description,
            file_io=file_io,
            shell_calls=shell_calls,
            network_calls=network,
            code_exec=exec_calls,
            return_type="unknown",
            writes_data=writes_data,
            reads_secrets=reads_secrets,
            hidden_params=[],
            raw_calls=list(calls)[:20],
        )

    def _compare_heuristic(self, tool, behavior: BehaviorSummary) -> DescVsResult:
        """Compare description vs behavior using heuristics (no AI)."""
        desc_lower = (behavior.description or "").lower()
        hidden = []

        # Shell execution
        if behavior.shell_calls and not any(k in desc_lower for k in ("execute", "run", "shell", "command", "process")):
            hidden.append(f"shell execution ({', '.join(behavior.shell_calls[:2])})")

        # File I/O
        if behavior.file_io and not any(k in desc_lower for k in ("file", "read", "write", "path", "directory")):
            hidden.append(f"file access ({', '.join(behavior.file_io[:2])})")

        # Network
        if behavior.network_calls and not any(k in desc_lower for k in ("http", "url", "fetch", "request", "api", "network", "web")):
            hidden.append(f"network calls ({', '.join(behavior.network_calls[:2])})")

        # Code execution
        if behavior.code_exec and not any(k in desc_lower for k in ("eval", "execute", "code", "script", "python")):
            hidden.append(f"code execution ({', '.join(behavior.code_exec[:2])})")

        # Secret access
        if behavior.reads_secrets and not any(k in desc_lower for k in ("credential", "secret", "auth", "config", "env")):
            hidden.append("reads environment variables / potential secrets")

        mismatch = len(hidden) > 0
        suspicious = len(hidden) >= 2 or bool(behavior.shell_calls and behavior.code_exec)

        if suspicious:
            quality = "SUSPICIOUS"
            risk = "HIGH"
        elif mismatch:
            quality = "MISMATCH"
            risk = "MEDIUM"
        else:
            quality = "FULL"
            risk = "INFO"

        return DescVsResult(
            tool_name=tool.name,
            description=behavior.description,
            behavior_summary=behavior,
            match=not mismatch,
            match_quality=quality,
            hidden_capabilities=hidden,
            risk_level=risk,
            summary=f"Behavior includes: {', '.join(hidden)}" if hidden else "Description matches observed behavior",
            is_tool_poisoning=suspicious and bool(behavior.shell_calls or behavior.code_exec),
            ai_available=False,
        )

    async def _compare_with_ai(self, tool, behavior: BehaviorSummary) -> DescVsResult:
        """Compare description vs behavior using Claude AI."""
        behavior_text = self._behavior_to_str(behavior)
        prompt = (
            f"Tool name: {tool.name}\n"
            f"Declared description: {behavior.description or '(none)'}\n"
            f"Parameters: {tool.params}\n\n"
            f"Behavior summary derived from static analysis:\n{behavior_text}\n\n"
            f"Relevant source:\n```python\n{tool.body_source[:1200]}\n```"
        )

        try:
            import httpx
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            body = {
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 512,
                "system": _DESC_VS_BEHAVIOR_SYSTEM,
                "messages": [{"role": "user", "content": prompt}],
            }
            async with httpx.AsyncClient(timeout=25.0) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=body,
                )
                resp.raise_for_status()
                text = resp.json()["content"][0]["text"].strip()
                if text.startswith("```"):
                    text = text.split("\n", 1)[1].rsplit("```", 1)[0]
                data = json.loads(text)

                return DescVsResult(
                    tool_name=tool.name,
                    description=behavior.description,
                    behavior_summary=behavior,
                    match=data.get("match", True),
                    match_quality=data.get("match_quality", "FULL"),
                    hidden_capabilities=data.get("hidden_capabilities", []),
                    risk_level=data.get("risk_level", "INFO"),
                    summary=data.get("summary", ""),
                    is_tool_poisoning=data.get("is_tool_poisoning", False),
                    ai_available=True,
                )
        except Exception as e:
            console.print(f"  [yellow]AI desc-vs-behavior error: {e}[/yellow]")
            # Fall back to heuristic
            result = self._compare_heuristic(tool, behavior)
            return result

    def _behavior_to_str(self, b: BehaviorSummary) -> str:
        """Human-readable behavior summary string."""
        parts = []
        if b.shell_calls:
            parts.append(f"shell: {', '.join(b.shell_calls[:2])}")
        if b.file_io:
            parts.append(f"file I/O: {', '.join(b.file_io[:2])}")
        if b.network_calls:
            parts.append(f"network: {', '.join(b.network_calls[:2])}")
        if b.code_exec:
            parts.append(f"code exec: {', '.join(b.code_exec[:2])}")
        if b.reads_secrets:
            parts.append("reads secrets/env")
        if b.writes_data:
            parts.append("writes data")
        return "; ".join(parts) if parts else "reads input, returns output"
