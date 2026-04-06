#!/usr/bin/env python3
"""MCPloit - MCP Security Testing Tool CLI."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

sys.path.insert(0, str(Path(__file__).parent))

from core.mcp_client import MCPClient, TransportType
from core.enumerator import Enumerator
from core.interactive import InteractiveShell
from modules.scanner import VulnerabilityScanner, get_available_detectors
from utils.output import print_banner, print_error, print_success, print_info
from payloads import PayloadManager
from exploits import ExploitEngine
from exploits.base_exploit import ExploitMode

app = typer.Typer(
    name="mcploit",
    help="MCP Security Testing Tool",
    add_completion=False,
)
console = Console()


def _get_transport_type(transport: Optional[str]) -> TransportType:
    """Parse transport type from string."""
    if not transport:
        return TransportType.AUTO
    try:
        return TransportType(transport.lower())
    except ValueError:
        print_error(f"Invalid transport type: {transport}")
        print_info("Valid options: stdio, sse, http")
        raise typer.Exit(1)


def _parse_headers(header_list: list[str]) -> dict[str, str]:
    """Parse 'Name: Value' header strings into a dict."""
    headers: dict[str, str] = {}
    for h in header_list:
        if ":" not in h:
            print_error(f"Invalid header format (expected 'Name: Value'): {h}")
            raise typer.Exit(1)
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()
    return headers


@app.command()
def connect(
    target: str = typer.Argument(..., help="Target MCP server (URL or file path)"),
    transport: Optional[str] = typer.Option(
        None,
        "--transport",
        "-t",
        help="Transport type: stdio, sse, http (auto-detected if not specified)",
    ),
    interactive: bool = typer.Option(
        True,
        "--interactive/--no-interactive",
        "-i/-I",
        help="Enter interactive shell after connecting",
    ),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="Extra HTTP header (repeatable): 'Authorization: Bearer <token>'",
    ),
):
    """Connect to an MCP server and enter interactive mode."""
    print_banner()

    transport_type = _get_transport_type(transport)
    headers = _parse_headers(header or [])

    async def _connect():
        client = MCPClient(target, transport_type, headers=headers)
        try:
            success = await client.connect()
            if not success:
                raise typer.Exit(1)

            if interactive:
                shell = InteractiveShell(client)
                await shell.run()
            else:
                # Just show basic info and exit
                console.print()
                await client.enumerate()

        finally:
            await client.disconnect()

    try:
        asyncio.run(_connect())
    except KeyboardInterrupt:
        print_info("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")
        raise typer.Exit(1)


@app.command("enum")
def enumerate_server(
    target: str = typer.Argument(..., help="Target MCP server (URL or file path)"),
    transport: Optional[str] = typer.Option(
        None,
        "--transport",
        "-t",
        help="Transport type: stdio, sse, http (auto-detected if not specified)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Export results to JSON file",
    ),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="Extra HTTP header (repeatable): 'Authorization: Bearer <token>'",
    ),
):
    """Enumerate MCP server and flag suspicious patterns."""
    print_banner()

    transport_type = _get_transport_type(transport)
    headers = _parse_headers(header or [])

    async def _enumerate():
        client = MCPClient(target, transport_type, headers=headers)
        try:
            success = await client.connect()
            if not success:
                raise typer.Exit(1)

            enumerator = Enumerator(client)
            await enumerator.enumerate()
            enumerator.print_results()

            if output:
                enumerator.export_json(output)

        finally:
            await client.disconnect()

    try:
        asyncio.run(_enumerate())
    except KeyboardInterrupt:
        print_info("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")
        raise typer.Exit(1)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target MCP server (URL or file path)"),
    transport: Optional[str] = typer.Option(None, "--transport", "-t",
        help="Transport type: stdio, sse, http (auto-detected if not specified)"),
    detectors: Optional[str] = typer.Option(
        "all", "--detectors", "-d",
        help="Detectors to run (comma-separated or 'all'). Options: " + ", ".join(get_available_detectors()),
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    output_md: Optional[str] = typer.Option(None, "--markdown", "-md", help="Export Markdown report"),
    probe: bool = typer.Option(False, "--probe", help="Enable active canary-based probing (injects payloads into tools)"),
    unsafe: bool = typer.Option(False, "--unsafe", help="Enable destructive payloads in active probe (requires --probe)"),
    schema: bool = typer.Option(False, "--schema", help="Run deep schema analysis"),
    neighbor_jack: bool = typer.Option(False, "--neighbor-jack", help="Include neighbor jack SSE tests"),
    probe_delay: int = typer.Option(500, "--probe-delay", help="Delay between probe attempts in ms"),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="Extra HTTP header (repeatable): 'Authorization: Bearer <token>'",
    ),
):
    """Scan MCP server for vulnerabilities (black-box mode).

    By default: passive metadata-based detection via detector registry.
    With --probe: active canary injection to confirm vulnerabilities (CONFIRMED confidence).
    With --schema: deep tool schema analysis (similar names, encoded descriptions, etc).

    Examples:
        mcploit scan http://localhost:9001/sse
        mcploit scan http://localhost:9001/sse --probe
        mcploit scan http://localhost:9001/sse --probe --schema --markdown report.md
        mcploit scan http://localhost:9001/sse --probe --unsafe
    """
    print_banner()
    transport_type = _get_transport_type(transport)
    headers = _parse_headers(header or [])
    detector_list = None
    if detectors and detectors.lower() != "all":
        detector_list = [d.strip() for d in detectors.split(",")]

    if unsafe and not probe:
        print_error("--unsafe requires --probe")
        raise typer.Exit(1)
    if probe:
        console.print("[yellow]⚠ Active probing enabled — injecting payloads into server tools[/yellow]")
    if unsafe:
        console.print("[red bold]⚠ UNSAFE mode — destructive payloads enabled[/red bold]")

    async def _scan():
        client = MCPClient(target, transport_type, headers=headers)
        try:
            success = await client.connect()
            if not success:
                raise typer.Exit(1)

            # Legacy detector-registry scan
            scanner = VulnerabilityScanner(detector_list)
            result = await scanner.scan(client)
            scanner.print_results(result)
            if output and not (probe or schema or neighbor_jack):
                scanner.export_json(result, output)

            # New black-box engine layers
            if probe or schema or neighbor_jack or output_md:
                from analysis.engine import AnalysisEngine, EngineConfig
                cfg = EngineConfig(
                    target_url=target,
                    run_sast=False, run_ast=False, run_ai=False,
                    run_desc_vs_behavior=False,
                    run_schema=schema,
                    run_active_probe=probe,
                    run_auth_detect=True,
                    run_neighbor_jack=neighbor_jack,
                    safe_probing=not unsafe,
                    probe_delay_ms=probe_delay,
                    output_json=output or "",
                    output_markdown=output_md or "",
                )
                engine = AnalysisEngine(client=client, config=cfg)
                await engine.run()

        finally:
            await client.disconnect()

    try:
        asyncio.run(_scan())
    except KeyboardInterrupt:
        print_info("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")
        raise typer.Exit(1)


@app.command()
def payloads(
    action: str = typer.Argument("list", help="Action: list (all modules) or show (specific module)"),
    module_type: Optional[str] = typer.Argument(None, help="Module type to show payloads for"),
):
    """List available exploit modules and payloads.

    Examples:
        mcploit payloads list              # List all modules
        mcploit payloads show pi           # Show prompt_injection payloads
        mcploit payloads show rce          # Show code_execution payloads
    """
    from rich.table import Table
    from rich.panel import Panel

    payload_manager = PayloadManager()

    if action == "list" or (action == "show" and not module_type):
        # List all modules
        console.print(Panel("[bold]Available Exploit Modules[/bold]", style="cyan"))

        table = Table(show_header=True)
        table.add_column("Module", style="cyan")
        table.add_column("Payloads", justify="right")
        table.add_column("Targets")

        module_info = {
            "prompt_injection": "Challenge 1, 6, Indirect Prompt servers, Wikipedia",
            "tool_poisoning": "Challenge 2, Malicious Tools",
            "path_traversal": "Challenge 3, Filesystem Workspace",
            "code_execution": "Challenges 8-9, Filesystem, Malicious Code",
            "token_theft": "Challenge 7",
            "tool_manipulation": "Challenges 4-5",
            "secrets_exposure": "Secrets PII server",
        }

        for module_name, targets in module_info.items():
            count = len(payload_manager.get_payloads(module_name))
            table.add_row(
                f"[green]\u2713[/green] {module_name}",
                str(count),
                targets,
            )

        console.print(table)
        console.print(f"\n[dim]Total: {payload_manager.get_total_count()} payloads[/dim]")
        console.print("\n[dim]Use 'mcploit payloads show <module>' to see payloads for a module[/dim]")

    elif action == "show" and module_type:
        # Show payloads for specific module
        payloads_list = payload_manager.get_payloads(module_type)

        if not payloads_list:
            print_error(f"Unknown module: {module_type}")
            console.print("[dim]Available: prompt_injection, tool_poisoning, path_traversal, "
                         "code_execution, token_theft, tool_manipulation, secrets_exposure[/dim]")
            raise typer.Exit(1)

        console.print(Panel(f"[bold]Payloads for {module_type}[/bold]", style="cyan"))

        table = Table(show_header=True)
        table.add_column("#", justify="right", style="dim")
        table.add_column("Name", style="cyan")
        table.add_column("Severity")
        table.add_column("Technique")
        table.add_column("Description")

        severity_colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "blue",
            "low": "green",
            "info": "dim",
        }

        for i, payload in enumerate(payloads_list, 1):
            color = severity_colors.get(payload.severity.value, "white")
            desc = payload.description[:45] + "..." if len(payload.description) > 45 else payload.description
            table.add_row(
                str(i),
                payload.name,
                f"[{color}]{payload.severity.value}[/{color}]",
                payload.technique,
                desc,
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(payloads_list)} payloads for {module_type}[/dim]")

    else:
        print_error(f"Unknown action: {action}")
        console.print("[dim]Usage: mcploit payloads list | mcploit payloads show <module>[/dim]")
        raise typer.Exit(1)


@app.command()
def exploit(
    target: str = typer.Argument(..., help="Target MCP server (URL or file path)"),
    module: str = typer.Option(
        ...,
        "--module",
        "-m",
        help="Exploit module to use (prompt_injection, path_traversal, code_execution, etc.)",
    ),
    transport: Optional[str] = typer.Option(
        None,
        "--transport",
        "-t",
        help="Transport type: stdio, sse, http (auto-detected if not specified)",
    ),
    tool: Optional[str] = typer.Option(
        None,
        "--tool",
        help="Specific tool to target",
    ),
    auto: bool = typer.Option(
        False,
        "--auto",
        "-a",
        help="Run all payloads automatically",
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive",
        "-i",
        help="Interactive payload selection",
    ),
    custom: bool = typer.Option(
        False,
        "--custom",
        "-c",
        help="Enter custom payload",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Export results to JSON file",
    ),
    header: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="Extra HTTP header (repeatable): 'Authorization: Bearer <token>'",
    ),
):
    """Exploit vulnerabilities on an MCP server.

    Examples:
        mcploit exploit http://localhost:9001/sse -m prompt_injection --auto
        mcploit exploit server.py -m path_traversal --interactive
        mcploit exploit http://localhost:9008/sse -m code_execution --tool execute_python_code --custom
    """
    import json

    print_banner()

    transport_type = _get_transport_type(transport)
    headers = _parse_headers(header or [])

    # Determine mode
    if custom:
        mode = ExploitMode.CUSTOM
    elif interactive:
        mode = ExploitMode.INTERACTIVE
    else:
        mode = ExploitMode.AUTO  # Default to auto

    async def _exploit():
        client = MCPClient(target, transport_type, headers=headers)
        try:
            success = await client.connect()
            if not success:
                print_error("Failed to connect to target")
                raise typer.Exit(1)

            # Create exploit engine
            engine = ExploitEngine(client)

            # Run exploit
            console.print(f"\n[bold cyan]Target:[/bold cyan] {target}")
            console.print(f"[bold cyan]Module:[/bold cyan] {module}")
            console.print(f"[bold cyan]Mode:[/bold cyan] {mode.value}")
            if tool:
                console.print(f"[bold cyan]Tool:[/bold cyan] {tool}")

            results = await engine.run(
                module_name=module,
                mode=mode,
                tool_name=tool,
            )

            # Export results if requested
            if output:
                export_data = engine.export_results()
                with open(output, "w") as f:
                    json.dump(export_data, f, indent=2)
                print_success(f"Results exported to {output}")

            # Return success status
            successful = [r for r in results if r.success]
            if successful:
                print_success(f"\n{len(successful)}/{len(results)} exploits successful")
            else:
                print_info(f"\n0/{len(results)} exploits successful")

        finally:
            await client.disconnect()

    try:
        asyncio.run(_exploit())
    except KeyboardInterrupt:
        print_info("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")
        raise typer.Exit(1)


@app.command()
def version():
    """Show MCPloit version."""
    console.print("[bold]MCPloit[/bold] v2.0.0 — Phase 2")


# ─────────────────────────────────────────────────────────────────────────────
# NEW COMMANDS — Phase 2
# ─────────────────────────────────────────────────────────────────────────────

def _get_burp_config(burp_host: str, burp_port: int, burp_ca: Optional[str]):
    """Build BurpProxyConfig if burp options are provided."""
    if burp_host:
        from integrations.burp_proxy import ProxyConfig
        return ProxyConfig(
            host=burp_host,
            port=burp_port,
            upstream_ca=burp_ca,
            verify_ssl=bool(burp_ca),
        )
    return None


@app.command()
def audit(
    source_path: str = typer.Argument(..., help="Path to MCP server source directory or file"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Export findings to JSON file"),
    output_md: Optional[str] = typer.Option(None, "--markdown", "-md", help="Export Markdown report"),
    severity: str = typer.Option("all", "--severity", "-s", help="Min severity: CRITICAL|HIGH|MEDIUM|LOW|all"),
    rules: Optional[str] = typer.Option(None, "--rules", help="Rule IDs to run (comma-separated, e.g. RCE-001,SEC-002)"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI-powered Layer 2 triage + Layer 3 desc-vs-behavior"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Anthropic API key (or set ANTHROPIC_API_KEY env var)"),
    no_desc_check: bool = typer.Option(False, "--no-desc-check", help="Skip description vs behavior check"),
    sast_only: bool = typer.Option(False, "--sast-only", help="Run SAST only (skip AST, AI, desc checks)"),
):
    """Full white-box audit — 3-layer analysis pipeline.

    Layer 1: SAST regex scan (eval/exec/shell=True/secrets/CVE patterns)
    Layer 2: AST data-flow + (optional) Claude AI triage and @tool review
    Layer 3: Description vs Behavior diff table (catches tool poisoning)

    Examples:
        mcploit audit ./my-mcp-server/
        mcploit audit ./server.py --severity HIGH
        mcploit audit ./server/ --ai -o findings.json --markdown report.md
        mcploit audit ./server/ --ai --api-key sk-ant-...
        mcploit audit ./server/ --sast-only --rules RCE-001,SEC-002
    """
    print_banner()

    path = Path(source_path)
    if not path.exists():
        print_error(f"Path not found: {source_path}")
        raise typer.Exit(1)

    if ai:
        import os
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            print_error("--ai requires ANTHROPIC_API_KEY env var or --api-key flag")
            console.print("[dim]Warning: source code will be sent to the Anthropic API for analysis.[/dim]")
            raise typer.Exit(1)
        console.print("[bold magenta]🤖 AI-enhanced analysis enabled — source will be sent to Anthropic API[/bold magenta]")

    from analysis.engine import AnalysisEngine, EngineConfig

    cfg = EngineConfig(
        source_path=source_path,
        run_sast=True,
        run_ast=not sast_only,
        run_ai=ai,
        run_desc_vs_behavior=not sast_only and not no_desc_check,
        run_schema=False,
        run_active_probe=False,
        run_auth_detect=False,
        run_neighbor_jack=False,
        api_key=api_key or "",
        output_json=output or "",
        output_markdown=output_md or "",
    )

    async def _audit():
        engine = AnalysisEngine(config=cfg)
        findings = await engine.run()

        # Apply severity filter
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        if severity.upper() != "ALL":
            min_sev = severity_order.get(severity.upper(), 4)
            findings = [f for f in findings if severity_order.get(f.severity.value, 4) <= min_sev]

        # Apply rule filter
        if rules:
            rule_ids = {r.strip() for r in rules.split(",")}
            findings = [f for f in findings if any(r in f.id for r in rule_ids)]

        crit = sum(1 for f in findings if f.severity.value == "CRITICAL")
        high = sum(1 for f in findings if f.severity.value == "HIGH")
        if crit:
            print_error(f"CRITICAL findings: {crit} — immediate action required")
        elif high:
            console.print(f"[yellow]HIGH findings: {high}[/yellow]")
        else:
            print_success("No HIGH or CRITICAL findings")

    try:
        asyncio.run(_audit())
    except KeyboardInterrupt:
        print_info("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")
        raise typer.Exit(1)


@app.command("neighbor-jack")
def neighbor_jack(
    target: str = typer.Argument(..., help="Target MCP server base URL (e.g. http://localhost:9001)"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    burp_host: str = typer.Option("", "--burp-host", help="Route tests through Burp proxy"),
    burp_port: int = typer.Option(8080, "--burp-port"),
    burp_ca: Optional[str] = typer.Option(None, "--burp-ca"),
):
    """Neighbor Jack test — SSE session isolation and cross-tenant data leakage.

    Tests for unauthenticated SSE access, session ID predictability,
    missing Origin validation, cross-session event leakage, and
    public network binding.

    Reference: https://vulnerablemcp.info/vuln/grafana-mcp-unauthenticated-sse.html

    Examples:
        mcploit neighbor-jack http://localhost:9001
        mcploit neighbor-jack http://target:9001 --burp-host 127.0.0.1
        mcploit neighbor-jack http://target:9001 -o nj_results.json
    """
    print_banner()
    from analysis.blackbox.neighbor_jack import NeighborJackTester

    burp_cfg = _get_burp_config(burp_host, burp_port, burp_ca)

    async def _nj():
        tester = NeighborJackTester(target, proxy_config=burp_cfg)
        result = await tester.run_all_tests()
        if output:
            findings_data = [
                {
                    "test": f.test_name,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "exploitable": f.exploitable,
                    "recommendation": f.recommendation,
                }
                for f in result.findings
            ]
            with open(output, "w") as fp:
                json.dump({"target": target, "findings": findings_data}, fp, indent=2)
            print_success(f"Results exported to {output}")

    try:
        asyncio.run(_nj())
    except KeyboardInterrupt:
        print_info("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")
        raise typer.Exit(1)


@app.command("metadata")
def metadata(
    target: Optional[str] = typer.Argument(None, help="Live MCP server URL or file path (optional)"),
    source_path: Optional[str] = typer.Option(None, "--source", "-s", help="Server source directory for white-box metadata"),
    transport: Optional[str] = typer.Option(None, "--transport", "-t"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
):
    """Extract rich metadata from an MCP server.

    Extracts: server identity, all tools with parameter schemas,
    suspected data sinks (shell/file/network), auth mechanisms,
    TLS info, framework detection, and CVE risk cross-reference.

    Examples:
        mcploit metadata http://localhost:9001/sse
        mcploit metadata --source ./my-server/
        mcploit metadata http://localhost:9001/sse --source ./src/ -o meta.json
    """
    print_banner()
    from analysis.metadata_extractor import MetadataExtractor

    if not target and not source_path:
        print_error("Provide a live target URL or --source path (or both)")
        raise typer.Exit(1)

    transport_type = _get_transport_type(transport) if target else TransportType.AUTO

    async def _metadata():
        client = None
        if target:
            client = MCPClient(target, transport_type)
            success = await client.connect()
            if not success:
                print_error("Failed to connect to target")
                raise typer.Exit(1)

        try:
            extractor = MetadataExtractor(client=client, source_path=source_path)
            meta = await extractor.extract()
            if output:
                with open(output, "w") as f:
                    json.dump(extractor.to_dict(), f, indent=2)
                print_success(f"Metadata exported to {output}")
        finally:
            if client:
                await client.disconnect()

    try:
        asyncio.run(_metadata())
    except KeyboardInterrupt:
        print_info("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")
        raise typer.Exit(1)


@app.command("cve-exploit")
def cve_exploit(
    target: str = typer.Argument(..., help="Target MCP server URL or file path"),
    cve: str = typer.Option(
        ..., "--cve", "-c",
        help="CVE to exploit: CVE-2025-67366 | CVE-2026-0755 | CVE-2026-23744 | whatsapp",
    ),
    transport: Optional[str] = typer.Option(None, "--transport", "-t"),
    tool: Optional[str] = typer.Option(None, "--tool", help="Specific tool to target"),
    inspector_url: Optional[str] = typer.Option(
        None, "--inspector-url",
        help="MCPJam Inspector URL (CVE-2026-23744 only, e.g. http://target:6274)",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    burp_host: str = typer.Option("", "--burp-host"),
    burp_port: int = typer.Option(8080, "--burp-port"),
    burp_ca: Optional[str] = typer.Option(None, "--burp-ca"),
):
    """Targeted CVE exploits against known vulnerable MCP components.

    Supported CVEs:
      CVE-2025-67366  — filesystem-mcp Path Traversal (read /etc/passwd etc.)
      CVE-2026-0755   — gemini-mcp-tool Command Injection
      CVE-2026-23744  — MCPJam Inspector RCE (HTB box)
      whatsapp        — WhatsApp MCP Message Exfiltration

    Examples:
        mcploit cve-exploit http://localhost:9001/sse --cve CVE-2025-67366
        mcploit cve-exploit http://target/sse --cve CVE-2026-23744 --inspector-url http://target:6274
        mcploit cve-exploit http://target/sse --cve whatsapp --burp-host 127.0.0.1
    """
    print_banner()

    cve_upper = cve.upper().strip()
    burp_cfg = _get_burp_config(burp_host, burp_port, burp_ca)
    transport_type = _get_transport_type(transport)

    async def _cve():
        results = []

        if cve_upper == "CVE-2026-23744":
            from exploits.cve_exploits import MCPJamInspectorExploit
            insp_url = inspector_url or target
            exploiter = MCPJamInspectorExploit(insp_url, proxy_config=burp_cfg)
            results = await exploiter.exploit()
        else:
            client = MCPClient(target, transport_type)
            success = await client.connect()
            if not success:
                print_error("Failed to connect to target")
                raise typer.Exit(1)
            try:
                if cve_upper == "CVE-2025-67366":
                    from exploits.cve_exploits import FilesystemMCPExploit
                    exploiter = FilesystemMCPExploit(client)
                    results = await exploiter.exploit(tool_name=tool)
                elif cve_upper == "CVE-2026-0755":
                    from exploits.cve_exploits import GeminiMCPExploit
                    exploiter = GeminiMCPExploit(client)
                    results = await exploiter.exploit(tool_name=tool)
                elif cve_upper in ("WHATSAPP", "WA", "WHATSAPP-EXFIL"):
                    from exploits.cve_exploits import WhatsAppMCPExploit
                    exploiter = WhatsAppMCPExploit(client)
                    results = await exploiter.exploit()
                else:
                    print_error(f"Unknown CVE: {cve}")
                    console.print("[dim]Supported: CVE-2025-67366, CVE-2026-0755, CVE-2026-23744, whatsapp[/dim]")
                    raise typer.Exit(1)
            finally:
                await client.disconnect()

        if output and results:
            export = [
                {
                    "cve": r.cve,
                    "tool": r.tool_name,
                    "payload": r.payload,
                    "success": r.success,
                    "evidence": r.evidence,
                    "extracted_data": r.extracted_data[:500] if r.extracted_data else "",
                }
                for r in results
            ]
            with open(output, "w") as f:
                json.dump(export, f, indent=2)
            print_success(f"Results exported to {output}")

    try:
        asyncio.run(_cve())
    except KeyboardInterrupt:
        print_info("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")
        raise typer.Exit(1)


@app.command("full-scan")
def full_scan(
    target: str = typer.Argument(..., help="Target MCP server URL or file path"),
    source_path: Optional[str] = typer.Option(None, "--source", "-s", help="Source dir for white-box analysis"),
    transport: Optional[str] = typer.Option(None, "--transport", "-t"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Export JSON report"),
    output_md: Optional[str] = typer.Option(None, "--markdown", "-md", help="Export Markdown report"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI Layer 2 triage + desc-vs-behavior"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    probe: bool = typer.Option(False, "--probe", help="Enable active canary probing"),
    unsafe: bool = typer.Option(False, "--unsafe", help="Destructive payloads (requires --probe)"),
    run_cve: bool = typer.Option(False, "--run-cve", help="Run CVE-specific exploit checks"),
    burp_host: str = typer.Option("", "--burp-host", help="Route through Burp proxy"),
    burp_port: int = typer.Option(8080, "--burp-port"),
    accept_disclaimer: bool = typer.Option(False, "--accept-disclaimer",
        help="Confirm this is authorized testing (required for active modes)"),
):
    """Full autonomous assessment — all MCPloit capabilities in one run.

    Runs: metadata → legacy scan → SAST (if --source) → AST data-flow →
          AI review (if --ai) → description-vs-behavior → schema analysis →
          auth detection → neighbor jack → active probing (if --probe) →
          CVE exploits (if --run-cve) → unified report.

    Examples:
        mcploit full-scan http://localhost:9001/sse
        mcploit full-scan http://target/sse --source ./src/ --ai --markdown report.md
        mcploit full-scan http://target/sse --probe --run-cve --accept-disclaimer -o full.json
        mcploit full-scan http://target/sse --source ./src --burp-host 127.0.0.1 --ai
    """
    import os
    print_banner()

    # Ethical disclaimer gate for active/destructive modes
    if (probe or run_cve or unsafe) and not accept_disclaimer:
        accepted = os.environ.get("MCPLOIT_ACCEPTED_DISCLAIMER", "").lower() in ("1", "true", "yes")
        if not accepted:
            console.print(
                "\n[bold yellow]⚠  DISCLAIMER REQUIRED[/bold yellow]\n"
                "Active testing modes (--probe, --run-cve, --unsafe) inject payloads into\n"
                "the target server. Only use on systems you are AUTHORIZED to test.\n"
                "Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA) and\n"
                "equivalent laws in your jurisdiction.\n\n"
                "Re-run with [bold]--accept-disclaimer[/bold] or set env var "
                "[bold]MCPLOIT_ACCEPTED_DISCLAIMER=1[/bold] to proceed."
            )
            raise typer.Exit(1)

    if ai:
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            print_error("--ai requires ANTHROPIC_API_KEY env var or --api-key flag")
            raise typer.Exit(1)
        console.print("[bold magenta]🤖 AI-enhanced mode — source will be sent to Anthropic API[/bold magenta]")

    console.print("\n[bold cyan]🚀 MCPloit Full Autonomous Assessment[/bold cyan]")
    transport_type = _get_transport_type(transport)

    async def _full():
        # ── Phase 1: Metadata ─────────────────────────────────────────────
        console.print("\n[bold]Phase 1 — Metadata Extraction[/bold]")
        from analysis.metadata_extractor import MetadataExtractor
        client = MCPClient(target, transport_type)
        if await client.connect():
            try:
                extractor = MetadataExtractor(client=client, source_path=source_path)
                await extractor.extract()
            finally:
                await client.disconnect()

        # ── Phase 2: Legacy detector scan ─────────────────────────────────
        console.print("\n[bold]Phase 2 — Vulnerability Detector Scan[/bold]")
        client = MCPClient(target, transport_type)
        if await client.connect():
            try:
                legacy_scanner = VulnerabilityScanner()
                legacy_result = await legacy_scanner.scan(client)
                legacy_scanner.print_results(legacy_result)
            finally:
                await client.disconnect()

        # ── Phase 3 & 4: Full AnalysisEngine (WB + BB) ───────────────────
        console.print("\n[bold]Phase 3 — Deep Analysis Engine[/bold]")
        from analysis.engine import AnalysisEngine, EngineConfig
        client = MCPClient(target, transport_type)
        if await client.connect():
            try:
                cfg = EngineConfig(
                    target_url=target,
                    source_path=source_path or "",
                    run_sast=bool(source_path),
                    run_ast=bool(source_path),
                    run_ai=ai,
                    run_desc_vs_behavior=bool(source_path),
                    run_schema=True,
                    run_active_probe=probe,
                    run_auth_detect=True,
                    run_neighbor_jack=target.startswith("http"),
                    api_key=api_key or "",
                    safe_probing=not unsafe,
                    output_json=output or "",
                    output_markdown=output_md or "",
                )
                engine = AnalysisEngine(client=client, config=cfg)
                await engine.run()
            finally:
                await client.disconnect()

        # ── Phase 5: CVE exploits (opt-in) ────────────────────────────────
        if run_cve:
            console.print("\n[bold]Phase 4 — CVE Exploit Checks[/bold]")
            from exploits.cve_exploits import (
                FilesystemMCPExploit,
                GeminiMCPExploit,
                MCPJamInspectorExploit,
                WhatsAppMCPExploit,
            )
            # MCPJam Inspector is HTTP-only — probe default port 6274
            if target.startswith("http"):
                parsed_target = target.split("/")[0] + "//" + target.split("/")[2].split(":")[0] + ":6274"
                await MCPJamInspectorExploit(parsed_target).exploit()

            client = MCPClient(target, transport_type)
            if await client.connect():
                try:
                    await FilesystemMCPExploit(client).exploit()
                    await GeminiMCPExploit(client).exploit()
                    await WhatsAppMCPExploit(client).exploit()
                finally:
                    await client.disconnect()
        else:
            console.print("\n[dim]Phase 4 — CVE exploits skipped (use --run-cve to enable)[/dim]")

        print_success("\n✅ Full assessment complete")

    try:
        asyncio.run(_full())
    except KeyboardInterrupt:
        print_info("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    disclaimer: bool = typer.Option(False, "--disclaimer", help="Print ethical use disclaimer and exit"),
):
    """MCPloit — MCP Security Testing Framework. Use only on authorized targets."""
    if disclaimer:
        console.print(
            "\n[bold]MCPloit — Ethical Use Disclaimer[/bold]\n\n"
            "MCPloit is designed for AUTHORIZED security testing of MCP servers.\n"
            "Use only against systems you own or have explicit written permission to test.\n\n"
            "Unauthorized use may violate:\n"
            "  • Computer Fraud and Abuse Act (CFAA) — United States\n"
            "  • Computer Misuse Act — United Kingdom\n"
            "  • Equivalent laws in your jurisdiction\n\n"
            "To suppress this warning in automation, set:\n"
            "  [bold]MCPLOIT_ACCEPTED_DISCLAIMER=1[/bold]\n\n"
            "The authors accept no liability for misuse."
        )
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


if __name__ == "__main__":
    app()
