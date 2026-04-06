"""Vulnerability Scanner - orchestrates all detectors."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Type

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .detectors.base_detector import (
    BaseDetector,
    DetectorContext,
    Vulnerability,
    Severity,
)
from .detectors.prompt_injection import PromptInjectionDetector
from .detectors.path_traversal import PathTraversalDetector
from .detectors.code_execution import CodeExecutionDetector
from .detectors.secrets_exposure import SecretsExposureDetector
from .detectors.tool_poisoning import ToolPoisoningDetector
from .detectors.token_theft import TokenTheftDetector
from .detectors.typosquatting import TyposquattingDetector

console = Console()


# Registry of all available detectors
DETECTOR_REGISTRY: dict[str, Type[BaseDetector]] = {
    "prompt_injection": PromptInjectionDetector,
    "path_traversal": PathTraversalDetector,
    "code_execution": CodeExecutionDetector,
    "secrets_exposure": SecretsExposureDetector,
    "tool_poisoning": ToolPoisoningDetector,
    "token_theft": TokenTheftDetector,
    "typosquatting": TyposquattingDetector,
}


@dataclass
class ScanResult:
    """Results from a vulnerability scan."""
    server_name: str
    server_version: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    detectors_run: list[str] = field(default_factory=list)
    tools_scanned: int = 0
    resources_scanned: int = 0
    prompts_scanned: int = 0

    @property
    def critical_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL])

    @property
    def high_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == Severity.HIGH])

    @property
    def medium_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM])

    @property
    def low_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == Severity.LOW])


class VulnerabilityScanner:
    """Orchestrates vulnerability detection across multiple detectors."""

    def __init__(self, detectors: list[str] | None = None):
        """Initialize scanner with specified detectors.

        Args:
            detectors: List of detector names to use, or None for all
        """
        self.detectors: list[BaseDetector] = []

        if detectors is None or "all" in detectors:
            # Use all detectors
            for detector_class in DETECTOR_REGISTRY.values():
                self.detectors.append(detector_class())
        else:
            # Use specified detectors
            for name in detectors:
                if name in DETECTOR_REGISTRY:
                    self.detectors.append(DETECTOR_REGISTRY[name]())
                else:
                    console.print(f"[yellow]Warning: Unknown detector '{name}', skipping[/yellow]")

    async def scan(self, client) -> ScanResult:
        """Run vulnerability scan on connected MCP server.

        Args:
            client: Connected MCPClient instance

        Returns:
            ScanResult with all findings
        """
        result = ScanResult(
            server_name="Unknown",
            server_version="Unknown"
        )

        # Get server info
        if client._client and client._client.initialize_result:
            init = client._client.initialize_result
            if init.serverInfo:
                result.server_name = init.serverInfo.name or "Unknown"
                result.server_version = init.serverInfo.version or "Unknown"

        # Gather context
        tools = []
        resources = []
        prompts = []

        try:
            tools = await client.list_tools()
            result.tools_scanned = len(tools)
        except Exception:
            pass

        try:
            resources = await client.list_resources()
            result.resources_scanned = len(resources)
        except Exception:
            pass

        try:
            prompts = await client.list_prompts()
            result.prompts_scanned = len(prompts)
        except Exception:
            pass

        # Create context for detectors
        context = DetectorContext(
            server_name=result.server_name,
            server_version=result.server_version,
            tools=tools,
            resources=resources,
            prompts=prompts
        )

        # Run all detectors
        for detector in self.detectors:
            result.detectors_run.append(detector.name)
            try:
                vulns = detector.detect(context)
                result.vulnerabilities.extend(vulns)
            except Exception as e:
                console.print(f"[yellow]Warning: Detector '{detector.name}' failed: {e}[/yellow]")

        # Deduplicate vulnerabilities
        result.vulnerabilities = self._deduplicate(result.vulnerabilities)

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        result.vulnerabilities.sort(key=lambda v: severity_order[v.severity])

        return result

    def _deduplicate(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique = []

        for vuln in vulnerabilities:
            # Create a key based on name, item, and core reason
            key = (vuln.name, vuln.item_type, vuln.item_name)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)

        return unique

    def print_results(self, result: ScanResult):
        """Print scan results to console."""
        # Header
        console.print()
        header = Text()
        header.append("Vulnerability Scan Results\n", style="bold")
        header.append(f"Target: {result.server_name} v{result.server_version}", style="dim")
        console.print(Panel(header, border_style="red"))

        # Summary
        console.print()
        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")

        summary_table.add_row("Tools Scanned", str(result.tools_scanned))
        summary_table.add_row("Resources Scanned", str(result.resources_scanned))
        summary_table.add_row("Prompts Scanned", str(result.prompts_scanned))
        summary_table.add_row("Detectors Run", str(len(result.detectors_run)))
        summary_table.add_row("", "")

        # Vulnerability counts with colors
        if result.critical_count > 0:
            summary_table.add_row(
                Text("CRITICAL", style="bold red"),
                Text(str(result.critical_count), style="bold red")
            )
        if result.high_count > 0:
            summary_table.add_row(
                Text("HIGH", style="bold yellow"),
                Text(str(result.high_count), style="bold yellow")
            )
        if result.medium_count > 0:
            summary_table.add_row(
                Text("MEDIUM", style="bold blue"),
                Text(str(result.medium_count), style="bold blue")
            )
        if result.low_count > 0:
            summary_table.add_row(
                Text("LOW", style="dim"),
                Text(str(result.low_count), style="dim")
            )

        total = len(result.vulnerabilities)
        summary_table.add_row("", "")
        summary_table.add_row(
            Text("TOTAL", style="bold"),
            Text(str(total), style="bold")
        )

        console.print(Panel(summary_table, title="Scan Summary", border_style="blue"))

        if not result.vulnerabilities:
            console.print()
            console.print("[green]No vulnerabilities detected![/green]")
            return

        # Detailed findings
        console.print()
        console.print("[bold]Detailed Findings:[/bold]")
        console.print()

        for vuln in result.vulnerabilities:
            self._print_vulnerability(vuln)

    def _print_vulnerability(self, vuln: Vulnerability):
        """Print a single vulnerability."""
        # Severity styling
        severity_styles = {
            Severity.CRITICAL: ("bold red", "🔴"),
            Severity.HIGH: ("bold yellow", "🟠"),
            Severity.MEDIUM: ("bold blue", "🟡"),
            Severity.LOW: ("dim", "⚪"),
            Severity.INFO: ("dim", "ℹ️"),
        }
        style, icon = severity_styles.get(vuln.severity, ("white", "•"))

        # Build output
        header = Text()
        header.append(f"[{vuln.severity.value}] ", style=style)
        header.append(vuln.name, style="bold")

        console.print(header)
        console.print(f"  [cyan]Type:[/cyan] {vuln.item_type}")
        console.print(f"  [cyan]Item:[/cyan] {vuln.item_name}")
        console.print(f"  [cyan]Confidence:[/cyan] {vuln.confidence.value}")
        console.print(f"  [cyan]Reason:[/cyan] {vuln.reason}")

        if vuln.exploit_hint:
            console.print(f"  [yellow]Exploit:[/yellow] {vuln.exploit_hint}")

        console.print()

    def export_json(self, result: ScanResult, filepath: str):
        """Export scan results to JSON file."""
        output = {
            "server": {
                "name": result.server_name,
                "version": result.server_version
            },
            "scan_info": {
                "tools_scanned": result.tools_scanned,
                "resources_scanned": result.resources_scanned,
                "prompts_scanned": result.prompts_scanned,
                "detectors_run": result.detectors_run
            },
            "summary": {
                "total": len(result.vulnerabilities),
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count
            },
            "vulnerabilities": [
                {
                    "name": v.name,
                    "severity": v.severity.value,
                    "confidence": v.confidence.value,
                    "item_type": v.item_type,
                    "item_name": v.item_name,
                    "reason": v.reason,
                    "exploit_hint": v.exploit_hint,
                    "details": v.details
                }
                for v in result.vulnerabilities
            ]
        }

        Path(filepath).write_text(json.dumps(output, indent=2))
        console.print(f"[green]Results exported to {filepath}[/green]")


def get_available_detectors() -> list[str]:
    """Get list of available detector names."""
    return list(DETECTOR_REGISTRY.keys())
