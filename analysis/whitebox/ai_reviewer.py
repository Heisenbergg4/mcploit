"""
AI Reviewer — Layer 2 of the MCPloit white-box analysis pipeline.

Uses the Anthropic Claude API to:
  1. Triage and enrich HIGH/CRITICAL SAST findings (reduce false positives)
  2. Deep-review each @tool function for logic bugs, auth issues,
     confused deputy, TOCTOU, SSRF, and other semantic vulnerabilities
     that regex cannot catch.

Cost control:
  - Only HIGH/CRITICAL SAST findings are sent to AI for triage
  - Each @tool function is reviewed once (source sent as a document block)
  - Results cached in-memory for the session to avoid duplicate API calls
  - Max tokens per request capped at 1024

Usage:
    reviewer = AIReviewer(api_key="sk-ant-...")  # or reads ANTHROPIC_API_KEY env
    enriched = await reviewer.triage_findings(sast_findings, source_context)
    tool_findings = await reviewer.review_tool_functions(tool_functions)
"""

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Optional

from rich.console import Console

from ..finding import UnifiedFinding, Severity, Confidence

console = Console()

# System prompt for AI triage / review
_TRIAGE_SYSTEM = """You are an expert MCP (Model Context Protocol) security analyst.
You are given a SAST finding and the relevant source code snippet.
Your job is to determine if the finding is a TRUE POSITIVE or FALSE POSITIVE,
and provide a concise assessment.

Respond ONLY with a JSON object (no markdown, no explanation outside JSON):
{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "reasoning": "one sentence max",
  "recommendation": "one sentence fix recommendation",
  "severity_adjustment": null | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
}"""

_TOOL_REVIEW_SYSTEM = """You are an expert MCP security analyst performing a deep security review of an MCP @tool function.

Analyze the function for ALL of the following vulnerability classes:
- Command / code injection (user input reaching shell, eval, exec)
- Path traversal (user input reaching file I/O without validation)
- SSRF (user-controlled URL passed to HTTP client)
- Confused deputy (tool performs privileged action without checking caller identity)
- Authentication bypass (missing auth checks)
- TOCTOU race conditions
- Secret / credential leakage in return values or logs
- Logic bugs enabling privilege escalation
- MCP-specific: tool description mismatches, hidden capabilities, rug pull vectors

Respond ONLY with a JSON object (no markdown fences):
{
  "findings": [
    {
      "title": "short title",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "category": "rce" | "path_traversal" | "ssrf" | "auth" | "secrets" | "logic" | "mcp_antipattern",
      "description": "2-3 sentence description",
      "evidence": "relevant code snippet (max 2 lines)",
      "recommendation": "specific fix"
    }
  ],
  "summary": "one paragraph overall assessment"
}"""


class AIReviewer:
    """
    Claude API-powered deep security reviewer.

    Requires ANTHROPIC_API_KEY env var or api_key constructor arg.
    """

    MODEL = "claude-sonnet-4-20250514"
    MAX_TOKENS = 1024

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._cache: dict[str, dict] = {}  # key → API response
        self._available = bool(self.api_key)

        if not self._available:
            console.print(
                "[yellow]⚠ AI Review disabled — set ANTHROPIC_API_KEY or pass --api-key[/yellow]"
            )

    def is_available(self) -> bool:
        return self._available

    async def triage_findings(
        self,
        findings: list[UnifiedFinding],
        source_files: dict[str, str],   # {filepath: source_content}
    ) -> list[UnifiedFinding]:
        """
        Triage HIGH/CRITICAL SAST findings using Claude.

        Returns the same list with:
          - False positives removed (or downgraded to INFO)
          - ai_flagged=True on confirmed true positives
          - severity adjusted if Claude recommends it
        """
        if not self._available:
            return findings

        triageable = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if not triageable:
            return findings

        console.print(f"  [magenta]🤖 AI triaging {len(triageable)} HIGH/CRITICAL findings...[/magenta]")

        enriched = []
        for f in findings:
            if f.severity not in (Severity.CRITICAL, Severity.HIGH):
                enriched.append(f)
                continue

            # Get source context
            context = self._get_source_context(f, source_files)
            result = await self._triage_one(f, context)

            if result.get("verdict") == "false_positive":
                # Downgrade to INFO rather than discard
                f.severity = Severity.INFO
                f.title = f"[FP] {f.title}"
                f.confidence = Confidence.LOW
                f.description += f"\n\n[AI] Assessed as likely false positive: {result.get('reasoning', '')}"
            else:
                f.ai_flagged = True
                f.confidence = Confidence(result.get("confidence", "MEDIUM"))
                if result.get("reasoning"):
                    f.description += f"\n\n[AI] {result['reasoning']}"
                if result.get("recommendation"):
                    f.recommendation = result["recommendation"]
                if result.get("severity_adjustment"):
                    try:
                        f.severity = Severity(result["severity_adjustment"])
                    except ValueError:
                        pass

            enriched.append(f)

        confirmed = sum(1 for f in enriched if f.ai_flagged)
        console.print(f"  [magenta]🤖 AI triage complete: {confirmed} findings confirmed[/magenta]")
        return enriched

    async def review_tool_functions(
        self,
        tool_functions: list,   # list[ToolFunction] from ast_helpers
    ) -> list[UnifiedFinding]:
        """
        Deep-review each @tool function for semantic vulnerabilities.

        Returns new UnifiedFindings with ai_flagged=True.
        """
        if not self._available or not tool_functions:
            return []

        console.print(f"  [magenta]🤖 AI reviewing {len(tool_functions)} @tool function(s)...[/magenta]")
        all_findings = []

        for tool in tool_functions:
            cache_key = f"tool:{tool.file}:{tool.name}"
            if cache_key in self._cache:
                result = self._cache[cache_key]
            else:
                result = await self._review_one_tool(tool)
                self._cache[cache_key] = result

            for raw in result.get("findings", []):
                try:
                    sev = Severity(raw.get("severity", "MEDIUM"))
                except ValueError:
                    sev = Severity.MEDIUM

                finding = UnifiedFinding(
                    id=f"WB-AI-{len(all_findings)+1:03d}",
                    title=raw.get("title", "AI-detected issue"),
                    severity=sev,
                    confidence=Confidence.HIGH,
                    source="ai_review",
                    category=raw.get("category", "logic"),
                    location=f"{tool.file}:{tool.line_start}",
                    description=raw.get("description", ""),
                    evidence=raw.get("evidence", ""),
                    recommendation=raw.get("recommendation", ""),
                    ai_flagged=True,
                    tool_name=tool.name,
                    file=tool.file,
                    line=tool.line_start,
                )
                all_findings.append(finding)

        console.print(f"  [magenta]🤖 AI review produced {len(all_findings)} finding(s)[/magenta]")
        return all_findings

    async def _triage_one(self, finding: UnifiedFinding, context: str) -> dict:
        """Send a single finding + context to Claude for triage."""
        prompt = (
            f"Finding:\n"
            f"  Rule: {finding.id}\n"
            f"  Title: {finding.title}\n"
            f"  Severity: {finding.severity.value}\n"
            f"  Evidence: {finding.evidence[:300]}\n\n"
            f"Source context:\n```python\n{context[:800]}\n```"
        )
        return await self._call_api(prompt, _TRIAGE_SYSTEM)

    async def _review_one_tool(self, tool) -> dict:
        """Send a tool function to Claude for deep review."""
        prompt = (
            f"Tool name: {tool.name}\n"
            f"Description: {tool.description}\n"
            f"Parameters: {tool.params}\n\n"
            f"Source code:\n```python\n{tool.body_source[:1500]}\n```"
        )
        return await self._call_api(prompt, _TOOL_REVIEW_SYSTEM)

    async def _call_api(self, prompt: str, system: str) -> dict:
        """Make an Anthropic API call and parse JSON response."""
        try:
            import httpx
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            body = {
                "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=body,
                )
                resp.raise_for_status()
                data = resp.json()
                text = data["content"][0]["text"].strip()
                # Strip markdown fences if present
                if text.startswith("```"):
                    text = text.split("\n", 1)[1].rsplit("```", 1)[0]
                return json.loads(text)
        except Exception as e:
            console.print(f"  [yellow]AI API error: {e}[/yellow]")
            return {}

    def _get_source_context(
        self,
        finding: UnifiedFinding,
        source_files: dict[str, str],
        window: int = 10,
    ) -> str:
        """Get source lines around a finding's location."""
        if not finding.file or finding.file not in source_files:
            return finding.evidence or ""
        lines = source_files[finding.file].splitlines()
        start = max(0, finding.line - window - 1)
        end = min(len(lines), finding.line + window)
        return "\n".join(lines[start:end])
