"""
ReportGenerator — renders UnifiedFindings as:
  1. Rich console output (severity-colored table + executive summary banner)
  2. findings.json (structured export)
  3. report.md  (human-readable Markdown with TOC, severity badges, CVE links)

The [AI] badge appears on any finding with ai_flagged=True.
"""

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .finding import UnifiedFinding, Severity, SEVERITY_COLORS, SEVERITY_ORDER

console = Console()

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

CATEGORY_LABELS = {
    "rce":             "Remote Code Execution",
    "path_traversal":  "Path Traversal",
    "secrets":         "Secret / Credential Exposure",
    "injection":       "Injection (SQL/LDAP/XML)",
    "mcp_antipattern": "MCP Anti-Pattern",
    "neighbor_jack":   "Neighbor Jack / SSE Isolation",
    "exfiltration":    "Data Exfiltration",
    "tool_poisoning":  "Tool Poisoning",
    "auth":            "Authentication Bypass",
    "active_probe":    "Active Probe (Canary Confirmed)",
    "schema":          "Schema / Tool Design Risk",
    "desc_mismatch":   "Description vs Behavior Mismatch",
}


class ReportGenerator:
    """
    Centralised report renderer for all MCPloit Phase 2 findings.

    Usage:
        rg = ReportGenerator(findings, target="http://localhost:9001/sse")
        rg.print_console()          # Rich console
        rg.save_json("out.json")    # JSON export
        rg.save_markdown("report.md")  # Markdown export
    """

    def __init__(
        self,
        findings: list[UnifiedFinding],
        target: str = "",
        source_path: str = "",
        scan_duration_s: float = 0.0,
    ):
        self.findings = sorted(findings, key=lambda f: f.sort_key())
        self.target = target
        self.source_path = source_path
        self.scan_duration_s = scan_duration_s
        self.generated_at = datetime.utcnow().isoformat() + "Z"
        self._counts = Counter(f.severity for f in findings)

    # ─────────────────────────────── Rich Console ────────────────────────────

    def print_console(self):
        """Print full Rich-formatted report to stdout."""
        self._print_summary_banner()
        self._print_findings_table()
        self._print_finding_details()

    def _print_summary_banner(self):
        """Top-level severity summary panel."""
        parts = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = self._counts.get(sev, 0)
            if count:
                color = SEVERITY_COLORS[sev]
                emoji = SEVERITY_EMOJI[sev]
                parts.append(f"[{color}]{emoji} {sev.value}: {count}[/{color}]")

        ai_count = sum(1 for f in self.findings if f.ai_flagged)
        total = len(self.findings)

        summary_text = "  |  ".join(parts) if parts else "[dim]No findings[/dim]"
        meta = f"\n[dim]Total: {total} findings"
        if ai_count:
            meta += f"  |  [bold magenta]{ai_count} AI-confirmed[/bold magenta][dim]"
        meta += f"  |  Scanned: {self.target or self.source_path}"
        meta += f"  |  {self.generated_at}[/dim]"

        console.print(Panel(
            summary_text + meta,
            title="[bold]MCPloit Phase 2 — Security Report[/bold]",
            border_style="red" if self._counts.get(Severity.CRITICAL, 0) else "yellow",
        ))

    def _print_findings_table(self):
        """Table of all findings."""
        if not self.findings:
            console.print("[dim]No findings to display.[/dim]")
            return

        table = Table(title="Findings", show_lines=True, expand=True)
        table.add_column("ID", style="bold dim", width=14)
        table.add_column("Sev", width=10)
        table.add_column("Title", max_width=38)
        table.add_column("Location", max_width=28)
        table.add_column("Conf", width=10)
        table.add_column("Source", width=14)
        table.add_column("CVE", width=16)

        for f in self.findings:
            color = SEVERITY_COLORS.get(f.severity, "white")
            ai = " [bold magenta][AI][/bold magenta]" if f.ai_flagged else ""
            loc = f.location or f.tool_name or (f"{Path(f.file).name}:{f.line}" if f.file else "—")
            table.add_row(
                f.id,
                f"[{color}]{f.severity.value}[/{color}]",
                f.title + ai,
                loc,
                f.confidence.value,
                f.source,
                f.cve or "—",
            )

        console.print(table)

    def _print_finding_details(self):
        """Expandable detail panels for HIGH+ findings."""
        high_plus = [f for f in self.findings if f.sort_key() <= 1]
        if not high_plus:
            return

        console.print("\n[bold]Detail — HIGH / CRITICAL Findings[/bold]")
        for f in high_plus:
            color = SEVERITY_COLORS.get(f.severity, "white")
            ai_tag = " [bold magenta][AI CONFIRMED][/bold magenta]" if f.ai_flagged else ""
            cve_line = f"\n[bold]CVE:[/bold] {f.cve}" if f.cve else ""
            body = (
                f"[bold]Category:[/bold] {CATEGORY_LABELS.get(f.category, f.category)}{cve_line}\n"
                f"[bold]Location:[/bold] {f.location or f.tool_name or f'{f.file}:{f.line}'}\n"
                f"[bold]Confidence:[/bold] {f.confidence.value}\n\n"
                f"{f.description}\n"
            )
            if f.evidence:
                body += f"\n[bold]Evidence:[/bold]\n[dim]{f.evidence[:400]}[/dim]\n"
            if f.recommendation:
                body += f"\n[bold]Fix:[/bold] {f.recommendation}"

            console.print(Panel(
                body,
                title=f"[{color}]{f.severity.value}[/{color}] {f.id}: {f.title}{ai_tag}",
                border_style=color,
            ))

    # ─────────────────────────────── JSON Export ─────────────────────────────

    def save_json(self, path: str):
        """Export findings to structured JSON."""
        data = {
            "generated_at": self.generated_at,
            "target": self.target,
            "source_path": self.source_path,
            "scan_duration_s": round(self.scan_duration_s, 2),
            "summary": {
                sev.value: self._counts.get(sev, 0)
                for sev in Severity
            },
            "total_findings": len(self.findings),
            "ai_confirmed_findings": sum(1 for f in self.findings if f.ai_flagged),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w") as fp:
            json.dump(data, fp, indent=2)
        console.print(f"[green]✓[/green] JSON report → {path}")

    # ─────────────────────────────── Markdown Export ─────────────────────────

    def save_markdown(self, path: str):
        """Export findings as a readable Markdown report with TOC and severity badges."""
        lines = []

        # Header
        lines.append("# MCPloit Security Report")
        lines.append("")
        lines.append(f"**Generated:** {self.generated_at}  ")
        if self.target:
            lines.append(f"**Target:** `{self.target}`  ")
        if self.source_path:
            lines.append(f"**Source:** `{self.source_path}`  ")
        lines.append(f"**Scan duration:** {self.scan_duration_s:.1f}s")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        total = len(self.findings)
        crit = self._counts.get(Severity.CRITICAL, 0)
        high = self._counts.get(Severity.HIGH, 0)
        ai_ct = sum(1 for f in self.findings if f.ai_flagged)

        lines.append(f"This assessment identified **{total} security finding(s)** across the target.")
        if crit:
            lines.append(f"**{crit} CRITICAL** finding(s) require immediate attention — they enable arbitrary code execution or credential theft.")
        if high:
            lines.append(f"**{high} HIGH** finding(s) represent significant risks and should be addressed in the next sprint.")
        if ai_ct:
            lines.append(f"**{ai_ct}** finding(s) were confirmed by Claude AI review (marked `[AI]`).")
        lines.append("")

        # Severity table
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in Severity:
            count = self._counts.get(sev, 0)
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev.value} | {count} |")
        lines.append("")

        # Table of Contents
        lines.append("## Table of Contents")
        lines.append("")
        for i, f in enumerate(self.findings, 1):
            anchor = f.id.lower().replace("-", "").replace(" ", "-")
            ai_tag = " `[AI]`" if f.ai_flagged else ""
            lines.append(f"{i}. [{f.id}: {f.title}](#{anchor}){ai_tag}")
        lines.append("")

        # Findings
        lines.append("## Findings")
        lines.append("")

        for f in self.findings:
            anchor = f.id.lower().replace("-", "").replace(" ", "-")
            emoji = SEVERITY_EMOJI.get(f.severity, "")
            ai_tag = " `[AI CONFIRMED]`" if f.ai_flagged else ""
            cve_badge = f" — **{f.cve}**" if f.cve else ""

            lines.append(f"### {anchor}")
            lines.append(f"#### {emoji} {f.id}: {f.title}{ai_tag}{cve_badge}")
            lines.append("")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Severity** | {f.severity.value} |")
            lines.append(f"| **Confidence** | {f.confidence.value} |")
            lines.append(f"| **Source** | {f.source} |")
            lines.append(f"| **Category** | {CATEGORY_LABELS.get(f.category, f.category)} |")
            loc = f.location or f.tool_name or (f"{f.file}:{f.line}" if f.file else "N/A")
            lines.append(f"| **Location** | `{loc}` |")
            if f.cve:
                lines.append(f"| **CVE** | [{f.cve}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={f.cve}) |")
            lines.append("")
            lines.append(f.description)
            lines.append("")

            if f.evidence:
                lines.append("**Evidence:**")
                lines.append("```")
                # Redact secrets in evidence
                redacted = _redact_secrets(f.evidence[:600])
                lines.append(redacted)
                lines.append("```")
                lines.append("")

            if f.recommendation:
                lines.append(f"**Recommendation:** {f.recommendation}")
                lines.append("")

            lines.append("---")
            lines.append("")

        content = "\n".join(lines)
        with open(path, "w") as fp:
            fp.write(content)
        console.print(f"[green]✓[/green] Markdown report → {path}")


def _redact_secrets(text: str) -> str:
    """Redact likely secret values from evidence snippets."""
    import re
    # AWS keys
    text = re.sub(r'AKIA[0-9A-Z]{16}', 'AKIA***REDACTED***', text)
    # OpenAI/Anthropic keys (allow hyphens in key body)
    text = re.sub(r'sk-[a-zA-Z0-9\-]{20,}', 'sk-***REDACTED***', text)
    # Private key material
    text = re.sub(r'-----BEGIN[^-]+PRIVATE KEY-----', '-----BEGIN PRIVATE KEY [REDACTED]-----', text)
    # Generic secrets (password/token/secret/key = 'value') — 4+ char values
    text = re.sub(
        r'(password|passwd|token|secret|api_key|apikey|credential)\s*[=:]\s*["\']?[^\s"\']{4,}["\']?',
        r'\1=***REDACTED***',
        text,
        flags=re.IGNORECASE,
    )
    return text
