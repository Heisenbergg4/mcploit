"""
AnalysisEngine — orchestrates the full MCPloit Phase 2 analysis pipeline.

Modes:
  WHITE-BOX (audit mode):
    Layer 1: SAST (regex + AST)
    Layer 2: AI triage of HIGH/CRITICAL SAST findings + @tool function review
    Layer 3: Description vs Behavior diff table

  BLACK-BOX (scan/probe mode):
    Schema analysis
    Active probing (opt-in, --probe flag)
    Auth detection
    Neighbor Jack tests

  COMBINED: both layers, unified output

All findings flow through UnifiedFinding → ReportGenerator.
"""

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console

from .finding import UnifiedFinding, Severity
from .report import ReportGenerator

console = Console()


@dataclass
class EngineConfig:
    """Configuration for a full analysis run."""
    # Targets
    target_url: str = ""
    source_path: str = ""

    # Feature flags
    run_sast: bool = True
    run_ast: bool = True
    run_ai: bool = False
    run_desc_vs_behavior: bool = True
    run_schema: bool = True
    run_active_probe: bool = False    # opt-in: --probe
    run_auth_detect: bool = True
    run_neighbor_jack: bool = False

    # Options
    api_key: str = ""
    safe_probing: bool = True         # canary-only payloads
    probe_delay_ms: int = 500
    min_severity: str = "INFO"        # filter output

    # Output
    output_json: str = ""
    output_markdown: str = ""


class AnalysisEngine:
    """
    Unified analysis engine — runs all enabled layers and merges findings.
    """

    def __init__(self, client=None, config: EngineConfig = None):
        self.client = client
        self.config = config or EngineConfig()
        self.findings: list[UnifiedFinding] = []
        self._start_time: float = 0.0

    async def run(self) -> list[UnifiedFinding]:
        """Execute the full analysis pipeline."""
        self._start_time = time.time()
        all_findings: list[UnifiedFinding] = []

        # ── WHITE-BOX LAYERS ─────────────────────────────────────────────────
        if self.config.source_path:
            all_findings.extend(await self._run_whitebox())

        # ── BLACK-BOX LAYERS ─────────────────────────────────────────────────
        if self.client:
            all_findings.extend(await self._run_blackbox())

        # Deduplicate and sort
        self.findings = self._deduplicate(all_findings)
        duration = time.time() - self._start_time

        # ── REPORT ───────────────────────────────────────────────────────────
        rg = ReportGenerator(
            self.findings,
            target=self.config.target_url,
            source_path=self.config.source_path,
            scan_duration_s=duration,
        )
        rg.print_console()

        if self.config.output_json:
            rg.save_json(self.config.output_json)
        if self.config.output_markdown:
            rg.save_markdown(self.config.output_markdown)

        return self.findings

    # ─────────────────────────────── White-box ───────────────────────────────

    async def _run_whitebox(self) -> list[UnifiedFinding]:
        findings = []
        src = self.config.source_path
        console.print(f"\n[bold cyan]⚪ White-Box Analysis → {src}[/bold cyan]")

        # Layer 1: SAST
        if self.config.run_sast:
            findings.extend(self._run_sast(src))

        # AST: extract tool functions for Layer 2 + 3
        tool_functions = []
        if self.config.run_ast or self.config.run_ai or self.config.run_desc_vs_behavior:
            tool_functions = self._extract_tool_functions(src)
            console.print(f"  [dim]Found {len(tool_functions)} @tool function(s)[/dim]")

        # Layer 1b: AST-based dangerous sink findings
        if self.config.run_ast and tool_functions:
            findings.extend(self._ast_to_findings(tool_functions))

        # Load source file contents for AI context
        source_files = {}
        if self.config.run_ai:
            source_files = self._load_source_files(src)

        # Layer 2: AI Review
        if self.config.run_ai and tool_functions:
            from .whitebox.ai_reviewer import AIReviewer
            reviewer = AIReviewer(api_key=self.config.api_key)
            if reviewer.is_available():
                # Triage SAST findings
                sast_only = [f for f in findings if f.source == "sast"]
                other = [f for f in findings if f.source != "sast"]
                triaged = await reviewer.triage_findings(sast_only, source_files)
                findings = other + triaged
                # Deep tool review
                tool_ai_findings = await reviewer.review_tool_functions(tool_functions)
                findings.extend(tool_ai_findings)

        # Layer 3: Description vs Behavior
        if self.config.run_desc_vs_behavior and tool_functions:
            from .whitebox.desc_vs_behavior import DescVsBehaviorChecker
            checker = DescVsBehaviorChecker(
                api_key=self.config.api_key,
                use_ai=self.config.run_ai,
            )
            desc_results = await checker.analyze(tool_functions)
            checker.print_table()
            findings.extend(checker.to_findings())

        return findings

    def _run_sast(self, src: str) -> list[UnifiedFinding]:
        """Run SAST and convert findings to UnifiedFindings."""
        from .whitebox.sast_scanner import SASTScanner
        scanner = SASTScanner()
        path = Path(src)
        raw = scanner.scan_file(path) if path.is_file() else scanner.scan_directory(path)

        unified = []
        for sf in raw:
            try:
                sev = Severity(sf.severity)
            except ValueError:
                sev = Severity.MEDIUM
            from .finding import Confidence
            unified.append(UnifiedFinding(
                id=f"WB-SAST-{len(unified)+1:03d}",
                title=sf.title,
                severity=sev,
                confidence=Confidence.MEDIUM,
                source="sast",
                category=sf.category,
                location=f"{Path(sf.file).name}:{sf.line}",
                description=sf.description,
                evidence=sf.code_snippet,
                recommendation=sf.recommendation,
                cve=sf.cve,
                file=sf.file,
                line=sf.line,
            ))
        console.print(f"  [dim]SAST: {len(unified)} finding(s)[/dim]")
        return unified

    def _extract_tool_functions(self, src: str) -> list:
        from .whitebox.ast_helpers import extract_tool_functions, find_entry_points
        path = Path(src)
        if path.is_file():
            return extract_tool_functions(str(path))
        entry_points = find_entry_points(src)
        tools = []
        seen_names = set()
        for ep in entry_points:
            for tf in extract_tool_functions(ep):
                if tf.name not in seen_names:
                    tools.append(tf)
                    seen_names.add(tf.name)
        return tools

    def _ast_to_findings(self, tool_functions: list) -> list[UnifiedFinding]:
        """Convert AST dangerous-sink detections to UnifiedFindings."""
        from .finding import Confidence
        findings = []
        for tf in tool_functions:
            if tf.has_shell_true:
                findings.append(UnifiedFinding(
                    id=f"WB-AST-{len(findings)+1:03d}",
                    title=f"subprocess shell=True in @tool '{tf.name}'",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    source="sast",
                    category="rce",
                    location=f"{Path(tf.file).name}:{tf.line_start}",
                    description=f"Tool function '{tf.name}' calls subprocess with shell=True, enabling command injection.",
                    evidence=tf.body_source[:200],
                    recommendation="Use subprocess with shell=False and a list of arguments.",
                    file=tf.file,
                    line=tf.line_start,
                ))
            for param, sinks in tf.reaches_sink.items():
                findings.append(UnifiedFinding(
                    id=f"WB-AST-{len(findings)+1:03d}",
                    title=f"Param '{param}' reaches sink in @tool '{tf.name}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    source="sast",
                    category="rce",
                    location=f"{Path(tf.file).name}:{tf.line_start}",
                    description=f"Data flow: parameter '{param}' in tool '{tf.name}' reaches dangerous sink(s): {sinks}.",
                    evidence=tf.body_source[:200],
                    recommendation="Validate and sanitize all tool parameters before using them in system calls.",
                    file=tf.file,
                    line=tf.line_start,
                ))
        return findings

    def _load_source_files(self, src: str) -> dict:
        files = {}
        p = Path(src)
        sources = [p] if p.is_file() else list(p.rglob("*.py"))[:20]
        for f in sources:
            try:
                files[str(f)] = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
        return files

    # ─────────────────────────────── Black-box ───────────────────────────────

    async def _run_blackbox(self) -> list[UnifiedFinding]:
        findings = []
        console.print(f"\n[bold cyan]⚫ Black-Box Analysis → {self.config.target_url or 'stdio'}[/bold cyan]")

        # ── Phase 1 legacy detector scan (bridged to UnifiedFinding) ────────
        try:
            from modules.scanner import VulnerabilityScanner as LegacyScanner
            legacy_scanner = LegacyScanner()
            result = await legacy_scanner.scan(self.client)
            bridged = self._bridge_legacy_findings(result.vulnerabilities)
            findings.extend(bridged)
            console.print(f"  [dim]Legacy detectors: {len(bridged)} finding(s)[/dim]")
        except Exception as e:
            console.print(f"  [yellow]Legacy scan error: {e}[/yellow]")

        # Schema analysis
        if self.config.run_schema:
            findings.extend(await self._run_schema_analysis())

        # Auth detection
        if self.config.run_auth_detect:
            findings.extend(await self._run_auth_detection())

        # Network scan (TLS, public exposure, debug ports)
        if self.config.target_url.startswith("http"):
            findings.extend(await self._run_network_scan())

        # Active probing (opt-in)
        if self.config.run_active_probe:
            findings.extend(await self._run_active_probing())

        # Neighbor Jack
        if self.config.run_neighbor_jack and self.config.target_url.startswith("http"):
            findings.extend(await self._run_neighbor_jack())

        return findings

    async def _run_schema_analysis(self) -> list[UnifiedFinding]:
        from .blackbox.schema_analyzer import SchemaAnalyzer
        try:
            tools = await self.client._client.list_tools()
            analyzer = SchemaAnalyzer()
            f = analyzer.analyze(tools)
            console.print(f"  [dim]Schema: {len(f)} finding(s)[/dim]")
            return f
        except Exception as e:
            console.print(f"  [yellow]Schema analysis failed: {e}[/yellow]")
            return []

    async def _run_auth_detection(self) -> list[UnifiedFinding]:
        from .blackbox.schema_analyzer import AuthDetector
        try:
            detector = AuthDetector(self.client, self.config.target_url)
            f = await detector.detect()
            console.print(f"  [dim]Auth: {len(f)} finding(s)[/dim]")
            return f
        except Exception as e:
            console.print(f"  [yellow]Auth detection failed: {e}[/yellow]")
            return []

    async def _run_active_probing(self) -> list[UnifiedFinding]:
        from .blackbox.active_prober import CommandInjectionProber, PathTraversalProber
        findings = []
        console.print("  [yellow]Active probing enabled[/yellow]")
        try:
            tools = await self.client._client.list_tools()
            cmd_prober = CommandInjectionProber(self.client, safe=self.config.safe_probing, delay_ms=self.config.probe_delay_ms)
            await cmd_prober.probe(tools)
            findings.extend(cmd_prober.to_findings())

            pt_prober = PathTraversalProber(self.client, safe=self.config.safe_probing, delay_ms=self.config.probe_delay_ms)
            await pt_prober.probe(tools)
            findings.extend(pt_prober.to_findings())

            console.print(f"  [dim]Active probe: {len(findings)} confirmed finding(s)[/dim]")
        except Exception as e:
            console.print(f"  [yellow]Active probing error: {e}[/yellow]")
        return findings

    async def _run_network_scan(self) -> list[UnifiedFinding]:
        from .blackbox.network_scanner import NetworkScanner
        try:
            scanner = NetworkScanner(self.config.target_url)
            result = await scanner.scan()
            console.print(f"  [dim]Network: {len(result.findings)} finding(s)[/dim]")
            return result.findings
        except Exception as e:
            console.print(f"  [yellow]Network scan error: {e}[/yellow]")
            return []

    async def _run_neighbor_jack(self) -> list[UnifiedFinding]:
        from .blackbox.neighbor_jack import NeighborJackTester
        from .finding import Confidence
        try:
            tester = NeighborJackTester(self.config.target_url)
            result = await tester.run_all_tests()
            findings = []
            for nj in result.findings:
                if not nj.exploitable:
                    continue
                try:
                    sev = Severity(nj.severity)
                except ValueError:
                    sev = Severity.MEDIUM
                findings.append(UnifiedFinding(
                    id=f"BB-NJ-{len(findings)+1:03d}",
                    title=nj.test_name,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    source="neighbor_jack",
                    category="neighbor_jack",
                    location=self.config.target_url,
                    description=nj.description,
                    evidence=nj.evidence,
                    recommendation=nj.recommendation,
                ))
            return findings
        except Exception as e:
            console.print(f"  [yellow]Neighbor Jack error: {e}[/yellow]")
            return []

    def _bridge_legacy_findings(self, vulnerabilities) -> list[UnifiedFinding]:
        """Convert Phase 1 Vulnerability objects to UnifiedFindings."""
        from .finding import Confidence
        findings = []
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        confidence_map = {
            "HIGH": Confidence.HIGH,
            "MEDIUM": Confidence.MEDIUM,
            "LOW": Confidence.LOW,
        }
        for v in vulnerabilities:
            sev = severity_map.get(getattr(v.severity, 'value', str(v.severity)), Severity.MEDIUM)
            conf = confidence_map.get(getattr(v.confidence, 'value', str(v.confidence)), Confidence.MEDIUM)
            findings.append(UnifiedFinding(
                id=f"BB-DET-{len(findings)+1:03d}",
                title=v.name,
                severity=sev,
                confidence=conf,
                source="black_box",
                category=v.name.lower().replace(" ", "_")[:30],
                location=f"{v.item_type}:{v.item_name}",
                description=v.reason,
                evidence=str(v.details)[:300] if v.details else "",
                recommendation=v.exploit_hint or "",
                tool_name=v.item_name if v.item_type == "tool" else "",
            ))
        return findings

    def _deduplicate(self, findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
        """Remove duplicate findings (same title + location)."""
        seen = set()
        result = []
        for f in findings:
            key = (f.title, f.location, f.file, f.line)
            if key not in seen:
                seen.add(key)
                result.append(f)
        return sorted(result, key=lambda f: f.sort_key())
