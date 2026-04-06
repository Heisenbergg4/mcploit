"""
Neighbor Jack Test Module.

Tests for SSE session isolation vulnerabilities where one MCP client
can read/inject into another client's session on the same server.

Reference: https://vulnerablemcp.info/vuln/grafana-mcp-unauthenticated-sse.html

Attack scenario:
  1. Server exposes SSE endpoint without per-session authentication
  2. Attacker connects and receives events meant for a different client
  3. Attacker can inject tool calls or read responses from neighbor sessions

Checks performed:
  - Unauthenticated SSE connection
  - Session ID prediction / enumeration
  - Cross-client event leakage
  - Missing Origin header validation
  - Public binding (0.0.0.0) exposure
"""

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@dataclass
class NeighborJackFinding:
    """A finding from neighbor jack testing."""
    test_name: str
    severity: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    exploitable: bool = False
    session_ids_found: list[str] = field(default_factory=list)


@dataclass
class NeighborJackResult:
    """Results from a full neighbor jack assessment."""
    target: str
    findings: list[NeighborJackFinding] = field(default_factory=list)
    sessions_intercepted: int = 0
    cross_tenant_data: list[str] = field(default_factory=list)


class NeighborJackTester:
    """
    Tests MCP SSE servers for session isolation and neighbor-jacking vulnerabilities.

    CVE Reference: Grafana MCP Unauthenticated SSE
    See: https://vulnerablemcp.info/vuln/grafana-mcp-unauthenticated-sse.html
    """

    # Common SSE endpoint paths
    SSE_PATHS = [
        "/sse",
        "/events",
        "/mcp/sse",
        "/api/sse",
        "/v1/sse",
        "/stream",
        "/mcp/stream",
    ]

    def __init__(self, target_url: str, proxy_config=None, timeout: float = 10.0):
        """
        Args:
            target_url: Base URL of the MCP server (e.g. http://localhost:9001)
            proxy_config: Optional BurpProxyConfig for traffic capture
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip("/")
        self.proxy_config = proxy_config
        self.timeout = timeout
        self.result = NeighborJackResult(target=target_url)

    async def run_all_tests(self) -> NeighborJackResult:
        """Run the full neighbor jack test suite."""
        if not HTTPX_AVAILABLE:
            console.print("[red]httpx not installed. Run: pip install httpx[/red]")
            return self.result

        console.print(f"\n[bold cyan]🔗 Neighbor Jack Tests → {self.target_url}[/bold cyan]")

        await self._test_unauthenticated_sse()
        await self._test_session_id_enumeration()
        await self._test_origin_header_validation()
        await self._test_cross_session_event_leakage()
        await self._test_post_messages_session_isolation()
        await self._test_public_binding()
        await self._test_session_fixation()

        self.print_results()
        return self.result

    async def _get_client(self) -> httpx.AsyncClient:
        """Create httpx client, optionally via Burp proxy."""
        kwargs = {"timeout": self.timeout, "follow_redirects": True, "verify": False}
        if self.proxy_config:
            kwargs["proxy"] = f"http://{self.proxy_config.host}:{self.proxy_config.port}"
        return httpx.AsyncClient(**kwargs)

    async def _test_unauthenticated_sse(self):
        """Test: Can we connect to SSE without any credentials?"""
        test_name = "Unauthenticated SSE Access"
        found_open = False

        async with await self._get_client() as client:
            for path in self.SSE_PATHS:
                url = f"{self.target_url}{path}"
                try:
                    # Use a short timeout to check if the endpoint exists
                    response = await client.get(
                        url,
                        headers={"Accept": "text/event-stream"},
                        timeout=3.0,
                    )
                    if response.status_code == 200:
                        content_type = response.headers.get("content-type", "")
                        if "event-stream" in content_type or "text/plain" in content_type:
                            self.result.findings.append(NeighborJackFinding(
                                test_name=test_name,
                                severity="CRITICAL",
                                description=f"SSE endpoint {path} accepts unauthenticated connections",
                                evidence=f"HTTP 200 at {url}, Content-Type: {content_type}",
                                recommendation=(
                                    "Require authentication (Bearer token or session cookie) on all SSE endpoints. "
                                    "See: https://vulnerablemcp.info/vuln/grafana-mcp-unauthenticated-sse.html"
                                ),
                                exploitable=True,
                            ))
                            found_open = True
                    elif response.status_code in (401, 403):
                        self.result.findings.append(NeighborJackFinding(
                            test_name=test_name,
                            severity="INFO",
                            description=f"SSE endpoint {path} returns {response.status_code} — auth enforced",
                            evidence=f"HTTP {response.status_code} at {url}",
                        ))
                except (httpx.ConnectError, httpx.TimeoutException):
                    pass

        if not found_open:
            self.result.findings.append(NeighborJackFinding(
                test_name=test_name,
                severity="INFO",
                description="No unauthenticated SSE endpoints found on common paths",
            ))

    async def _test_session_id_enumeration(self):
        """Test: Are session IDs predictable/sequential (integer IDs, short tokens)?"""
        test_name = "Session ID Predictability"
        session_ids = []

        async with await self._get_client() as client:
            for _ in range(3):
                for path in self.SSE_PATHS:
                    url = f"{self.target_url}{path}"
                    try:
                        resp = await client.get(
                            url,
                            headers={"Accept": "text/event-stream"},
                            timeout=2.0,
                        )
                        # Look for session IDs in response headers or initial event
                        for header in ["X-Session-Id", "Set-Cookie", "X-Client-Id", "Location"]:
                            val = resp.headers.get(header, "")
                            if val:
                                session_ids.append(val)

                        # Check first chunk of SSE data
                        text = resp.text[:500]
                        sid_matches = re.findall(r'session[_\-]?id["\s:=]+([a-zA-Z0-9\-_]{4,})', text, re.I)
                        session_ids.extend(sid_matches)

                    except Exception:
                        pass

        if session_ids:
            # Check if IDs look predictable
            predictable = any(
                re.match(r'^\d{1,8}$', sid) or  # integer
                re.match(r'^[a-f0-9]{4,8}$', sid) or  # short hex
                sid in ("", "0", "null", "undefined")  # empty
                for sid in session_ids
            )
            severity = "CRITICAL" if predictable else "MEDIUM"
            self.result.findings.append(NeighborJackFinding(
                test_name=test_name,
                severity=severity,
                description=f"Found {len(session_ids)} session identifier(s)",
                evidence=f"Session IDs observed: {session_ids[:5]}",
                recommendation=(
                    "Use cryptographically random UUIDs for session IDs (uuid4). "
                    "Never use sequential integers or short tokens."
                ),
                exploitable=predictable,
                session_ids_found=session_ids[:10],
            ))

    async def _test_origin_header_validation(self):
        """Test: Does the server validate the Origin header on SSE connections?"""
        test_name = "Origin Header Validation"
        malicious_origin = "https://evil.attacker.com"

        async with await self._get_client() as client:
            for path in self.SSE_PATHS:
                url = f"{self.target_url}{path}"
                try:
                    resp = await client.get(
                        url,
                        headers={
                            "Accept": "text/event-stream",
                            "Origin": malicious_origin,
                        },
                        timeout=3.0,
                    )
                    if resp.status_code == 200:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        if acao == "*" or acao == malicious_origin:
                            self.result.findings.append(NeighborJackFinding(
                                test_name=test_name,
                                severity="HIGH",
                                description=(
                                    f"SSE endpoint at {path} accepts cross-origin requests "
                                    f"from arbitrary origins (ACAO: {acao or 'not set'})"
                                ),
                                evidence=f"Origin: {malicious_origin} → HTTP 200",
                                recommendation=(
                                    "Set Access-Control-Allow-Origin to specific trusted origins. "
                                    "Validate Origin header server-side before establishing SSE connection."
                                ),
                                exploitable=True,
                            ))
                        break
                except Exception:
                    pass

    # MCP SSE protocol boilerplate events seen on every healthy connection —
    # both sessions always receive these, so they must be excluded from the
    # cross-session overlap check to avoid false positives.
    _SSE_PROTOCOL_EVENTS: set[str] = {
        "",                       # empty keep-alive lines
        "{}",
        "ping",
        "pong",
    }
    _SSE_PROTOCOL_PREFIXES = (
        '{"jsonrpc"',             # initial JSON-RPC handshake
        '/messages?sessionId=',   # endpoint URL announcement
        '/message?session',
        'sessionId',
        '"method":"ping"',
        '"method":"sse/',
    )

    @staticmethod
    def _is_protocol_boilerplate(event_data: str) -> bool:
        """Return True if the SSE data line is standard MCP transport boilerplate."""
        stripped = event_data.strip()
        if stripped in MCPJamInspectorExploit._SSE_PROTOCOL_EVENTS if False else (
            stripped in NeighborJackTester._SSE_PROTOCOL_EVENTS
        ):
            return True
        for prefix in NeighborJackTester._SSE_PROTOCOL_PREFIXES:
            if prefix in stripped:
                return True
        return False

    async def _test_cross_session_event_leakage(self):
        """
        Test: Open two SSE connections simultaneously and check if substantive
        non-boilerplate events from one session appear in the other.

        NOTE: Both sessions will always share the same MCP protocol-level
        handshake events (endpoint URL, ping, etc.).  These are filtered out
        before checking for real cross-tenant leakage.
        """
        test_name = "Cross-Session Event Leakage"
        leaked_data = []

        # Find an active SSE endpoint
        active_path = None
        async with await self._get_client() as client:
            for path in self.SSE_PATHS:
                try:
                    resp = await client.get(
                        f"{self.target_url}{path}",
                        headers={"Accept": "text/event-stream"},
                        timeout=2.0,
                    )
                    if resp.status_code == 200:
                        active_path = path
                        break
                except Exception:
                    pass

        if not active_path:
            return

        # Read events from two concurrent connections, strip protocol boilerplate
        async def read_sse_events(url: str, collector: list, duration: float = 3.0):
            try:
                async with httpx.AsyncClient(verify=False, timeout=duration + 1) as c:
                    async with c.stream("GET", url, headers={"Accept": "text/event-stream"}) as resp:
                        deadline = time.time() + duration
                        async for line in resp.aiter_lines():
                            if time.time() > deadline:
                                break
                            if line.startswith("data:"):
                                payload = line[5:].strip()
                                # Only keep substantive, non-boilerplate events
                                if (
                                    len(payload) > 10
                                    and not NeighborJackTester._is_protocol_boilerplate(payload)
                                ):
                                    collector.append(payload)
            except Exception:
                pass

        url = f"{self.target_url}{active_path}"
        session1_events: list[str] = []
        session2_events: list[str] = []

        await asyncio.gather(
            read_sse_events(url, session1_events, 3.0),
            read_sse_events(url, session2_events, 3.0),
        )

        # Check for cross-contamination of substantive events only
        if session1_events and session2_events:
            overlap = set(session1_events) & set(session2_events)
            if overlap:
                for item in overlap:
                    leaked_data.append(item[:200])

                self.result.findings.append(NeighborJackFinding(
                    test_name=test_name,
                    severity="CRITICAL",
                    description=(
                        f"Cross-session event leakage detected! "
                        f"{len(overlap)} substantive event(s) received by two independent sessions"
                    ),
                    evidence=f"Leaked events: {list(overlap)[:3]}",
                    recommendation=(
                        "Implement per-session event queues. Never broadcast events to all connected clients. "
                        "Use session tokens to route events to the correct client only."
                    ),
                    exploitable=True,
                ))
                self.result.cross_tenant_data.extend(leaked_data)
                self.result.sessions_intercepted += 1

    async def _test_post_messages_session_isolation(self):
        """
        Test: Does POST /messages reject requests with a forged / random sessionId?

        MCP SSE transport has two surfaces:
          GET  /sse               → opens the event stream
          POST /messages?sessionId=<token>  → submits JSON-RPC requests

        If the server accepts arbitrary sessionId values it allows cross-session
        message injection — an attacker can submit tool calls into a victim's session.
        """
        test_name = "POST /messages Session Isolation"
        message_paths = [
            "/messages",
            "/message",
            "/mcp/messages",
            "/api/messages",
        ]
        forged_session = "mcploit-forge-" + uuid.uuid4().hex[:12]
        # A valid-looking but minimal MCP initialize request
        test_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcploit-nj-test", "version": "1.0"},
            },
        }

        async with await self._get_client() as client:
            for path in message_paths:
                url = f"{self.target_url}{path}?sessionId={forged_session}"
                try:
                    resp = await client.post(
                        url,
                        json=test_body,
                        headers={"Content-Type": "application/json"},
                        timeout=3.0,
                    )
                    if resp.status_code in (200, 202):
                        # Server accepted a message for a session it never issued
                        self.result.findings.append(NeighborJackFinding(
                            test_name=test_name,
                            severity="HIGH",
                            description=(
                                f"POST {path} accepted a message with a forged sessionId — "
                                "no session validation is enforced"
                            ),
                            evidence=(
                                f"HTTP {resp.status_code} on POST {url} "
                                f"with forged sessionId={forged_session}"
                            ),
                            recommendation=(
                                "Validate that sessionId was issued by this server and is currently active. "
                                "Reject 404/400 any request whose sessionId is unknown."
                            ),
                            exploitable=True,
                        ))
                        return
                    elif resp.status_code in (400, 404, 403):
                        self.result.findings.append(NeighborJackFinding(
                            test_name=test_name,
                            severity="INFO",
                            description=f"POST {path} correctly rejected forged sessionId ({resp.status_code})",
                        ))
                        return
                except (httpx.ConnectError, httpx.TimeoutException):
                    pass

    @staticmethod
    def _is_private_host(host: str) -> bool:
        """Return True for loopback and RFC-1918 private addresses."""
        if host in ("localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"):
            return True
        if host.startswith("10.") or host.startswith("192.168."):
            return True
        # 172.16.0.0/12 → 172.16.x.x – 172.31.x.x
        parts = host.split(".")
        if len(parts) == 4 and parts[0] == "172":
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
        return False

    async def _test_public_binding(self):
        """Test: Is the server binding to 0.0.0.0 making it publicly accessible?"""
        test_name = "Public Network Binding"
        parsed = urlparse(self.target_url)
        host = parsed.hostname

        if host in ("0.0.0.0", "::") or not self._is_private_host(host):
            self.result.findings.append(NeighborJackFinding(
                test_name=test_name,
                severity="HIGH",
                description=f"Server appears to be bound to non-localhost address: {host}",
                evidence=f"Target URL: {self.target_url}",
                recommendation=(
                    "MCP servers should bind to 127.0.0.1 only. "
                    "If multi-client access is needed, use a reverse proxy with authentication."
                ),
                exploitable=True,
            ))

    async def _test_session_fixation(self):
        """Test: Can we force a known session ID onto the server?"""
        test_name = "Session Fixation"
        fixed_session = "mcploit-fixed-session-12345"

        async with await self._get_client() as client:
            for path in self.SSE_PATHS:
                url = f"{self.target_url}{path}"
                try:
                    resp = await client.get(
                        url,
                        headers={
                            "Accept": "text/event-stream",
                            "X-Session-Id": fixed_session,
                            "Cookie": f"session_id={fixed_session}",
                        },
                        timeout=3.0,
                    )
                    if resp.status_code == 200:
                        # Check if the server accepted or reflected our session ID
                        set_cookie = resp.headers.get("Set-Cookie", "")
                        if fixed_session in set_cookie or fixed_session in resp.text[:500]:
                            self.result.findings.append(NeighborJackFinding(
                                test_name=test_name,
                                severity="HIGH",
                                description="Server may accept client-supplied session identifiers (session fixation)",
                                evidence=f"Server reflected provided session ID: {fixed_session}",
                                recommendation=(
                                    "Always generate session IDs server-side. "
                                    "Ignore and reject client-provided session identifiers."
                                ),
                                exploitable=True,
                            ))
                        break
                except Exception:
                    pass

    def print_results(self):
        """Print test results as a Rich formatted table."""
        table = Table(title="Neighbor Jack Test Results", show_lines=True, expand=True)
        table.add_column("Test", style="bold")
        table.add_column("Severity", width=10)
        table.add_column("Description", max_width=50)
        table.add_column("Exploitable", width=12)

        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }

        for f in self.result.findings:
            color = severity_colors.get(f.severity, "white")
            exploitable_str = "[red]YES[/red]" if f.exploitable else "[green]NO[/green]"
            table.add_row(
                f.test_name,
                f"[{color}]{f.severity}[/{color}]",
                f.description,
                exploitable_str,
            )

        console.print(table)

        if self.result.cross_tenant_data:
            console.print(Panel(
                "\n".join(self.result.cross_tenant_data[:5]),
                title="[red]⚠ Cross-Tenant Data Intercepted[/red]",
                border_style="red",
            ))

        exploitable_count = sum(1 for f in self.result.findings if f.exploitable)
        console.print(f"\n[bold]Neighbor Jack Summary:[/bold] {exploitable_count} exploitable issues found")
