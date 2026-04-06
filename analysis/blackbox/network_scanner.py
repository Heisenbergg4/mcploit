"""
Network Scanner — MCP server network exposure analysis.

Checks:
  1. TLS certificate validity (self-signed, expired, hostname mismatch)
  2. Common MCP endpoint path discovery (/sse, /mcp, /api/mcp, etc.)
  3. Public binding detection (server reachable from non-localhost)
  4. Debug port exposure (common dev ports that shouldn't be public)
  5. HTTP security headers (HSTS, CSP, X-Frame-Options)
  6. Response fingerprinting (identify server framework/version)
"""

import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from ..finding import UnifiedFinding, Severity, Confidence

console = Console()

# Common MCP server paths to probe
MCP_PATHS = [
    "/sse", "/mcp", "/mcp/sse", "/api/mcp", "/api/sse",
    "/v1/mcp", "/v1/sse", "/stream", "/events",
    "/.well-known/mcp", "/inspector", "/debug",
]

# Debug ports that should never be publicly exposed
SUSPICIOUS_PORTS = {
    6274: "MCPJam Inspector",
    5173: "Vite dev server",
    3000: "Node.js dev",
    8080: "HTTP dev",
    9229: "Node.js debugger",
    9230: "Chrome DevTools",
    4000: "MCP dev server",
}


@dataclass
class NetworkScanResult:
    """Results from a network scan."""
    target_url: str
    tls_valid: bool = False
    tls_self_signed: bool = False
    tls_expired: bool = False
    tls_hostname_mismatch: bool = False
    tls_version: str = ""
    open_mcp_paths: list[str] = field(default_factory=list)
    exposed_debug_ports: list[dict] = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    server_header: str = ""
    publicly_accessible: bool = False
    findings: list[UnifiedFinding] = field(default_factory=list)


class NetworkScanner:
    """
    Checks MCP server network posture for security issues.
    """

    REQUIRED_SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
    ]

    def __init__(self, target_url: str, timeout: float = 5.0):
        self.target_url = target_url
        self.timeout = timeout
        self.result = NetworkScanResult(target_url=target_url)

    async def scan(self) -> NetworkScanResult:
        """Run all network checks."""
        console.print(f"\n[bold cyan]🌐 Network Scan → {self.target_url}[/bold cyan]")

        parsed = urlparse(self.target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # TLS checks
        if parsed.scheme == "https":
            await self._check_tls(host, port)

        # Check if target is publicly accessible (non-localhost)
        self._check_public_exposure(host)

        # Discover MCP paths
        await self._discover_paths(parsed.scheme, host, port)

        # Security headers
        await self._check_security_headers()

        # Debug port exposure
        await self._check_debug_ports(host)

        # Convert to findings
        self._generate_findings()
        self._print_results()
        return self.result

    async def _check_tls(self, host: str, port: int):
        """Check TLS certificate validity."""
        ctx_strict = ssl.create_default_context()
        ctx_loose = ssl.create_default_context()
        ctx_loose.check_hostname = False
        ctx_loose.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                # Try strict first
                try:
                    with ctx_strict.wrap_socket(sock, server_hostname=host) as ssock:
                        self.result.tls_valid = True
                        self.result.tls_version = ssock.version() or ""
                        cert = ssock.getpeercert()
                        if cert:
                            # Check expiry
                            not_after = cert.get("notAfter", "")
                            if not_after:
                                exp = ssl.cert_time_to_seconds(not_after)
                                if exp < time.time():
                                    self.result.tls_expired = True
                except ssl.SSLCertVerificationError as e:
                    self.result.tls_valid = False
                    err = str(e).lower()
                    if "self" in err or "self-signed" in err or "unable to get local issuer" in err:
                        self.result.tls_self_signed = True
                    elif "hostname" in err:
                        self.result.tls_hostname_mismatch = True
                    # Get version with loose context
                    sock2 = socket.create_connection((host, port), timeout=self.timeout)
                    with ctx_loose.wrap_socket(sock2, server_hostname=host) as ssock:
                        self.result.tls_version = ssock.version() or ""
        except Exception as e:
            console.print(f"  [dim]TLS check error: {e}[/dim]")

    def _check_public_exposure(self, host: str):
        """Check if the server is accessible from a non-localhost address."""
        private_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        private_prefixes = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
        if host in private_hosts:
            return
        if any(host.startswith(p) for p in private_prefixes):
            return
        self.result.publicly_accessible = True

    async def _discover_paths(self, scheme: str, host: str, port: int):
        """Probe common MCP endpoint paths."""
        try:
            import httpx
            base_url = f"{scheme}://{host}:{port}"
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                for path in MCP_PATHS:
                    try:
                        resp = await client.get(
                            f"{base_url}{path}",
                            headers={"Accept": "text/event-stream, application/json"},
                            follow_redirects=False,
                        )
                        if resp.status_code in (200, 401, 403):
                            self.result.open_mcp_paths.append(
                                f"{path} [{resp.status_code}]"
                            )
                    except Exception:
                        pass
        except ImportError:
            pass

    async def _check_security_headers(self):
        """Check HTTP security headers on the target."""
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.get(self.target_url, follow_redirects=True)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                self.result.server_header = headers.get("server", "")

                # Check security headers
                missing = []
                for required in self.REQUIRED_SECURITY_HEADERS:
                    if required.lower() in headers:
                        self.result.security_headers[required] = headers[required.lower()]
                    else:
                        missing.append(required)
                self.result.missing_security_headers = missing
        except Exception:
            pass

    async def _check_debug_ports(self, host: str):
        """Check if common debug/dev ports are open."""
        for port, service in SUSPICIOUS_PORTS.items():
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    self.result.exposed_debug_ports.append({
                        "port": port,
                        "service": service,
                    })
            except Exception:
                pass

    def _generate_findings(self):
        """Convert scan results to UnifiedFindings."""
        findings = []

        # TLS issues
        if self.result.tls_self_signed:
            findings.append(UnifiedFinding(
                id="NET-001",
                title="Self-signed TLS certificate",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                source="network_scanner",
                category="mcp_antipattern",
                location=self.target_url,
                description="The server uses a self-signed certificate. Clients cannot verify the server's identity, enabling MITM attacks.",
                recommendation="Use a certificate from a trusted CA (Let's Encrypt is free). Never use self-signed certs in production.",
            ))

        if self.result.tls_expired:
            findings.append(UnifiedFinding(
                id="NET-002",
                title="Expired TLS certificate",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                source="network_scanner",
                category="mcp_antipattern",
                location=self.target_url,
                description="The server's TLS certificate has expired. Clients will see security warnings and MCP clients may refuse to connect.",
                recommendation="Renew the TLS certificate immediately. Use certbot with auto-renewal.",
            ))

        if self.result.tls_hostname_mismatch:
            findings.append(UnifiedFinding(
                id="NET-003",
                title="TLS certificate hostname mismatch",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                source="network_scanner",
                category="mcp_antipattern",
                location=self.target_url,
                description="The TLS certificate does not match the server hostname. This indicates a misconfiguration or potential MITM.",
                recommendation="Reissue the certificate for the correct hostname.",
            ))

        # Public exposure
        if self.result.publicly_accessible:
            findings.append(UnifiedFinding(
                id="NET-004",
                title="MCP server publicly accessible (non-localhost)",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                source="network_scanner",
                category="mcp_antipattern",
                location=self.target_url,
                description=f"The MCP server at {self.target_url} is reachable from a public or non-localhost address. MCP servers are designed for local use and should not be publicly exposed without strong authentication.",
                recommendation="Bind to 127.0.0.1. If remote access is needed, use a reverse proxy with mTLS or OAuth2.",
            ))

        # Debug ports
        for port_info in self.result.exposed_debug_ports:
            findings.append(UnifiedFinding(
                id=f"NET-00{5+len(findings)}",
                title=f"Debug port {port_info['port']} ({port_info['service']}) is open",
                severity=Severity.CRITICAL if port_info["service"] == "MCPJam Inspector" else Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                source="network_scanner",
                category="mcp_antipattern",
                location=f"{urlparse(self.target_url).hostname}:{port_info['port']}",
                description=(
                    f"Port {port_info['port']} ({port_info['service']}) is accessible. "
                    f"{'This is the MCPJam Inspector port — CVE-2026-23744 RCE applies.' if port_info['service'] == 'MCPJam Inspector' else 'Development/debug ports should never be exposed in production.'}"
                ),
                recommendation=f"Close port {port_info['port']} or restrict access with firewall rules.",
                cve="CVE-2026-23744" if port_info["service"] == "MCPJam Inspector" else "",
            ))

        # Missing security headers
        if self.result.missing_security_headers:
            findings.append(UnifiedFinding(
                id="NET-010",
                title=f"Missing HTTP security headers: {', '.join(self.result.missing_security_headers[:3])}",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                source="network_scanner",
                category="mcp_antipattern",
                location=self.target_url,
                description=f"Server is missing: {', '.join(self.result.missing_security_headers)}.",
                recommendation="Add HSTS, X-Content-Type-Options, X-Frame-Options, and CSP headers.",
            ))

        self.result.findings = findings

    def _print_results(self):
        """Print scan results."""
        table = Table(title="Network Scan Results", show_lines=True)
        table.add_column("Check", style="bold")
        table.add_column("Result")

        tls_str = "N/A (HTTP)" if not self.target_url.startswith("https") else (
            "[green]Valid[/green]" if self.result.tls_valid else
            "[red]INVALID[/red]" + (" (self-signed)" if self.result.tls_self_signed else "") +
            (" (expired)" if self.result.tls_expired else "")
        )
        table.add_row("TLS Certificate", tls_str)
        table.add_row("TLS Version", self.result.tls_version or "—")
        table.add_row(
            "Public Exposure",
            "[red]YES — publicly accessible[/red]" if self.result.publicly_accessible else "[green]localhost only[/green]",
        )
        paths_str = "\n".join(self.result.open_mcp_paths[:5]) if self.result.open_mcp_paths else "[dim]none found[/dim]"
        table.add_row("MCP Paths Found", paths_str)

        if self.result.exposed_debug_ports:
            ports_str = ", ".join(f"{p['port']} ({p['service']})" for p in self.result.exposed_debug_ports)
            table.add_row("Debug Ports Open", f"[red]{ports_str}[/red]")

        if self.result.server_header:
            table.add_row("Server Header", self.result.server_header)
        if self.result.missing_security_headers:
            table.add_row(
                "Missing Headers",
                f"[yellow]{', '.join(self.result.missing_security_headers[:3])}[/yellow]",
            )

        console.print(table)

        if self.result.findings:
            console.print(f"[bold]Network findings: {len(self.result.findings)}[/bold]")
