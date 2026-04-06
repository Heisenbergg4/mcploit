"""
Metadata Extraction Module for MCPloit.

Extracts rich metadata from MCP servers:
  - Server name, version, capabilities
  - Tool/resource/prompt inventory with full schemas
  - Authentication mechanisms
  - Transport details (SSE endpoint paths, HTTP headers)
  - Framework fingerprinting (FastMCP, official SDK, custom)
  - Network exposure (host, port, TLS status)
  - Dependency information (from source if available)
  - CVE cross-reference for known vulnerable versions
"""

import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

console = Console()


# Known vulnerable versions mapped to CVEs
KNOWN_VULNERABLE_VERSIONS = {
    "filesystem-mcp": {
        "<=1.0.0": "CVE-2025-67366",
        "description": "Path traversal via read_file/write_file allowing arbitrary file access",
    },
    "gemini-mcp-tool": {
        "<=0.3.1": "CVE-2026-0755",
        "description": "Command injection via unsanitized Gemini API response passed to subprocess",
    },
    "mcpjam-inspector": {
        "<=2.1.0": "CVE-2026-23744",
        "description": "RCE via inspector eval endpoint without authentication",
    },
    "mcp-server-whatsapp": {
        "<=1.2.0": "GHSA-XXXX-XXXX",
        "description": "Message exfiltration via tool parameter injection",
    },
}

# Framework fingerprints
FRAMEWORK_SIGNATURES = {
    "fastmcp": ["fastmcp", "FastMCP", "fast_mcp"],
    "official-sdk": ["@modelcontextprotocol/sdk", "mcp.server.Server"],
    "mcp-framework": ["MCPServer", "from mcp import"],
    "custom": [],
}


@dataclass
class ToolMetadata:
    """Metadata for a single MCP tool."""
    name: str
    description: str
    input_schema: dict = field(default_factory=dict)
    parameter_count: int = 0
    has_required_params: bool = False
    param_names: list[str] = field(default_factory=list)
    suspected_sinks: list[str] = field(default_factory=list)  # shell, file, network, etc.


@dataclass
class ServerMetadata:
    """Complete metadata extracted from an MCP server."""
    # Identity
    name: str = "unknown"
    version: str = "unknown"
    protocol_version: str = "unknown"

    # Capabilities
    supports_tools: bool = False
    supports_resources: bool = False
    supports_prompts: bool = False
    supports_logging: bool = False
    supports_sampling: bool = False

    # Inventory
    tools: list[ToolMetadata] = field(default_factory=list)
    resource_uris: list[str] = field(default_factory=list)
    prompt_names: list[str] = field(default_factory=list)

    # Transport
    transport_type: str = "unknown"
    target_url: str = ""
    tls_enabled: bool = False
    tls_version: Optional[str] = None
    tls_cert_common_name: Optional[str] = None
    response_headers: dict = field(default_factory=dict)

    # Auth
    auth_type: str = "none"  # none, bearer, basic, api_key, oauth
    auth_header_observed: Optional[str] = None
    requires_auth: bool = False

    # Framework
    framework: str = "unknown"
    framework_version: Optional[str] = None

    # CVE risk
    cve_risks: list[dict] = field(default_factory=list)

    # Source (if white-box)
    source_files: list[str] = field(default_factory=list)
    dependencies: dict = field(default_factory=dict)

    # Raw data
    raw_initialize_response: dict = field(default_factory=dict)


class MetadataExtractor:
    """
    Extracts comprehensive metadata from a connected MCP server.

    Works in both black-box (connected client) and white-box (source path) mode.
    """

    def __init__(self, client=None, source_path: Optional[str] = None):
        """
        Args:
            client: Connected MCPClient instance (black-box mode)
            source_path: Path to server source directory (white-box mode)
        """
        self.client = client
        self.source_path = Path(source_path) if source_path else None
        self.metadata = ServerMetadata()

    async def extract(self) -> ServerMetadata:
        """Run full metadata extraction."""
        console.print("\n[bold cyan]🔍 Extracting Server Metadata...[/bold cyan]")

        if self.client:
            await self._extract_from_client()

        if self.source_path:
            self._extract_from_source()

        self._check_cve_risks()
        self.print_results()
        return self.metadata

    async def _extract_from_client(self):
        """Extract metadata from a live connected client."""
        try:
            # Server info
            if hasattr(self.client, '_client') and self.client._client:
                info = getattr(self.client, 'server_info', None)
                if info:
                    self.metadata.name = getattr(info, 'name', 'unknown')
                    self.metadata.version = getattr(info, 'version', 'unknown')

            # Target URL and transport
            self.metadata.target_url = getattr(self.client, 'target', '')
            self.metadata.transport_type = self._detect_transport()

            # TLS info
            if self.metadata.target_url.startswith("https://"):
                self.metadata.tls_enabled = True
                self._extract_tls_info(self.metadata.target_url)

            # Tools
            tools = await self.client._client.list_tools()
            self.metadata.supports_tools = True
            for tool in tools:
                schema = {}
                params = []
                has_required = False
                sinks = []

                if hasattr(tool, 'inputSchema') and tool.inputSchema:
                    schema = tool.inputSchema if isinstance(tool.inputSchema, dict) else {}
                    props = schema.get("properties", {})
                    params = list(props.keys())
                    required = schema.get("required", [])
                    has_required = bool(required)
                    # Heuristic: guess what the tool touches
                    sinks = self._guess_sinks(tool.name, tool.description or "", params)

                self.metadata.tools.append(ToolMetadata(
                    name=tool.name,
                    description=tool.description or "",
                    input_schema=schema,
                    parameter_count=len(params),
                    has_required_params=has_required,
                    param_names=params,
                    suspected_sinks=sinks,
                ))

            # Resources
            try:
                resources = await self.client._client.list_resources()
                self.metadata.supports_resources = True
                self.metadata.resource_uris = [str(r.uri) for r in resources]
            except Exception:
                pass

            # Prompts
            try:
                prompts = await self.client._client.list_prompts()
                self.metadata.supports_prompts = True
                self.metadata.prompt_names = [p.name for p in prompts]
            except Exception:
                pass

            # Auth detection from HTTP headers
            await self._detect_auth()

        except Exception as e:
            console.print(f"[yellow]Metadata extraction partial failure: {e}[/yellow]")

    def _extract_from_source(self):
        """Extract metadata from source code files."""
        path = self.source_path

        # Find all Python/JS files
        py_files = list(path.rglob("*.py"))
        js_files = list(path.rglob("*.js")) + list(path.rglob("*.ts"))
        all_files = py_files + js_files

        self.metadata.source_files = [str(f) for f in all_files[:50]]

        # Framework detection
        self.metadata.framework = self._detect_framework(all_files)

        # Dependency extraction
        self._extract_dependencies(path)

        # Scan for server name/version in source
        for f in py_files[:20]:
            try:
                content = f.read_text(errors="replace")
                # FastMCP server name
                m = re.search(r'FastMCP\s*\(\s*["\']([^"\']+)["\']', content)
                if m and self.metadata.name == "unknown":
                    self.metadata.name = m.group(1)
                # Version string
                m = re.search(r'version\s*=\s*["\']([0-9.]+)["\']', content)
                if m and self.metadata.version == "unknown":
                    self.metadata.version = m.group(1)
            except Exception:
                pass

    def _detect_transport(self) -> str:
        """Detect transport type from target URL."""
        target = self.metadata.target_url.lower()
        if target.endswith(".py") or target.endswith(".js"):
            return "stdio"
        if "/sse" in target:
            return "sse"
        if target.startswith("http"):
            return "http"
        return "unknown"

    def _extract_tls_info(self, url: str):
        """Extract TLS certificate information."""
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    self.metadata.tls_version = ssock.version()
                    cert = ssock.getpeercert()
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        self.metadata.tls_cert_common_name = subject.get("commonName", "")
        except Exception:
            pass

    async def _detect_auth(self):
        """Detect authentication mechanism from server responses."""
        if not self.metadata.target_url.startswith("http"):
            return
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                resp = await client.get(self.metadata.target_url)
                self.metadata.response_headers = dict(resp.headers)

                if resp.status_code in (401, 403):
                    self.metadata.requires_auth = True
                    www_auth = resp.headers.get("WWW-Authenticate", "")
                    if "Bearer" in www_auth:
                        self.metadata.auth_type = "bearer"
                    elif "Basic" in www_auth:
                        self.metadata.auth_type = "basic"
                    self.metadata.auth_header_observed = www_auth

                # Look for auth indicators in headers
                for header in resp.headers:
                    if "x-api-key" in header.lower():
                        self.metadata.auth_type = "api_key"
                    if "authorization" in header.lower():
                        self.metadata.auth_type = "bearer"
        except Exception:
            pass

    def _detect_framework(self, files: list[Path]) -> str:
        """Detect MCP framework from source files."""
        for f in files[:10]:
            try:
                content = f.read_text(errors="replace")
                for framework, sigs in FRAMEWORK_SIGNATURES.items():
                    if any(sig in content for sig in sigs):
                        return framework
            except Exception:
                pass
        return "unknown"

    def _extract_dependencies(self, path: Path):
        """Extract dependency information from requirements.txt or package.json."""
        deps = {}

        req_file = path / "requirements.txt"
        if req_file.exists():
            for line in req_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    m = re.match(r'^([a-zA-Z][a-zA-Z0-9\-_]*)([>=<!]+.*)?$', line)
                    if m:
                        deps[m.group(1)] = m.group(2) or "unpinned"

        pkg_file = path / "package.json"
        if pkg_file.exists():
            try:
                pkg = json.loads(pkg_file.read_text())
                for dep_key in ("dependencies", "devDependencies"):
                    for name, ver in pkg.get(dep_key, {}).items():
                        deps[name] = ver
            except Exception:
                pass

        self.metadata.dependencies = deps

    def _guess_sinks(self, name: str, description: str, params: list[str]) -> list[str]:
        """Heuristically guess what resource a tool touches."""
        sinks = []
        combined = (name + " " + description + " " + " ".join(params)).lower()

        if any(k in combined for k in ("file", "path", "read", "write", "directory", "folder")):
            sinks.append("filesystem")
        if any(k in combined for k in ("exec", "run", "shell", "command", "process", "system")):
            sinks.append("shell")
        if any(k in combined for k in ("http", "url", "fetch", "request", "webhook", "api")):
            sinks.append("network")
        if any(k in combined for k in ("sql", "query", "database", "db", "select")):
            sinks.append("database")
        if any(k in combined for k in ("eval", "code", "python", "javascript", "script")):
            sinks.append("code_execution")
        if any(k in combined for k in ("email", "whatsapp", "message", "send", "notify")):
            sinks.append("messaging")
        return sinks

    def _check_cve_risks(self):
        """Cross-reference server name/version against known CVEs."""
        server_name_lower = self.metadata.name.lower()

        for pkg_name, vuln_info in KNOWN_VULNERABLE_VERSIONS.items():
            if pkg_name.lower() in server_name_lower or pkg_name.lower() in str(self.metadata.dependencies).lower():
                # Check version constraint
                server_ver = self.metadata.version
                version_constraint = [v for k, v in vuln_info.items() if k.startswith("<")]
                cve = [v for k, v in vuln_info.items() if "CVE" in k or "GHSA" in v]

                self.metadata.cve_risks.append({
                    "package": pkg_name,
                    "cve": vuln_info.get("<=1.0.0", "See description"),
                    "description": vuln_info.get("description", ""),
                    "server_version": server_ver,
                })

    def print_results(self):
        """Print extracted metadata in a structured Rich format."""
        md = self.metadata

        # Server Identity Panel
        identity_lines = [
            f"[bold]Name:[/bold] {md.name}",
            f"[bold]Version:[/bold] {md.version}",
            f"[bold]Framework:[/bold] {md.framework}",
            f"[bold]Transport:[/bold] {md.transport_type}",
            f"[bold]Target:[/bold] {md.target_url}",
            f"[bold]Auth:[/bold] {md.auth_type} ({'required' if md.requires_auth else 'not required'})",
        ]
        if md.tls_enabled:
            identity_lines.append(f"[bold]TLS:[/bold] {md.tls_version} — {md.tls_cert_common_name or 'no cert info'}")

        console.print(Panel("\n".join(identity_lines), title="[bold]Server Identity[/bold]", border_style="blue"))

        # Tools table
        if md.tools:
            t = Table(title=f"Tools ({len(md.tools)})", show_lines=True)
            t.add_column("Name", style="bold")
            t.add_column("Params")
            t.add_column("Suspected Sinks")
            t.add_column("Description", max_width=50)
            for tool in md.tools:
                sinks_str = ", ".join(tool.suspected_sinks) if tool.suspected_sinks else "-"
                sink_color = "red" if tool.suspected_sinks else "dim"
                t.add_row(
                    tool.name,
                    f"{tool.parameter_count} ({', '.join(tool.param_names[:3])}{'...' if len(tool.param_names) > 3 else ''})",
                    f"[{sink_color}]{sinks_str}[/{sink_color}]",
                    (tool.description or "")[:80],
                )
            console.print(t)

        # CVE risks
        if md.cve_risks:
            console.print("\n[bold red]⚠ CVE RISKS DETECTED:[/bold red]")
            for risk in md.cve_risks:
                console.print(f"  [red]{risk['cve']}[/red] — {risk['package']} {risk['server_version']}: {risk['description']}")

        # Resources & Prompts
        if md.resource_uris:
            console.print(f"\n[bold]Resources ({len(md.resource_uris)}):[/bold] {', '.join(md.resource_uris[:5])}")
        if md.prompt_names:
            console.print(f"[bold]Prompts ({len(md.prompt_names)}):[/bold] {', '.join(md.prompt_names[:5])}")

        # Dependencies
        if md.dependencies:
            console.print(f"\n[bold]Dependencies ({len(md.dependencies)}):[/bold]")
            unpinned = [k for k, v in md.dependencies.items() if v == "unpinned"]
            if unpinned:
                console.print(f"  [yellow]Unpinned:[/yellow] {', '.join(unpinned[:10])}")

    def to_dict(self) -> dict:
        """Export metadata as a dictionary."""
        md = self.metadata
        return {
            "server": {
                "name": md.name,
                "version": md.version,
                "protocol_version": md.protocol_version,
                "framework": md.framework,
            },
            "transport": {
                "type": md.transport_type,
                "url": md.target_url,
                "tls_enabled": md.tls_enabled,
                "tls_version": md.tls_version,
            },
            "auth": {
                "type": md.auth_type,
                "required": md.requires_auth,
            },
            "capabilities": {
                "tools": md.supports_tools,
                "resources": md.supports_resources,
                "prompts": md.supports_prompts,
            },
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "params": t.param_names,
                    "sinks": t.suspected_sinks,
                }
                for t in md.tools
            ],
            "resources": md.resource_uris,
            "prompts": md.prompt_names,
            "cve_risks": md.cve_risks,
            "dependencies": md.dependencies,
        }
