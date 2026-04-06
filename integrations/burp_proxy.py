"""
Burp Suite Proxy Integration for MCPloit.

Routes all MCP HTTP/SSE traffic through a Burp Suite proxy,
making every request interceptable, repeatable, and modifiable.
Supports autonomous testing with request/response logging in Burp format.
"""

import asyncio
import json
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx
from rich.console import Console

console = Console()


@dataclass
class ProxyConfig:
    """Configuration for Burp Suite proxy."""
    host: str = "127.0.0.1"
    port: int = 8080
    upstream_ca: Optional[str] = None      # Path to Burp's exported CA cert
    intercept_responses: bool = True
    log_file: Optional[str] = "burp_mcploit.log"
    verify_ssl: bool = False               # Disable for Burp MITM


@dataclass
class ProxiedRequest:
    """A captured MCP request/response pair."""
    timestamp: float
    method: str
    url: str
    headers: dict
    body: Optional[str]
    response_status: Optional[int] = None
    response_headers: Optional[dict] = None
    response_body: Optional[str] = None
    duration_ms: float = 0.0
    tool_name: Optional[str] = None
    payload_used: Optional[str] = None


class BurpProxyClient:
    """
    HTTP client that routes all traffic through Burp Suite proxy.

    Usage:
        config = ProxyConfig(host="127.0.0.1", port=8080)
        async with BurpProxyClient(config) as client:
            resp = await client.post("http://target/mcp", json={...})
    """

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.captured: list[ProxiedRequest] = []
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        proxy_url = f"http://{self.config.host}:{self.config.port}"

        # Build SSL context - trust Burp's CA if provided
        ssl_context = ssl.create_default_context()
        if self.config.upstream_ca:
            ssl_context.load_verify_locations(self.config.upstream_ca)
        else:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self._client = httpx.AsyncClient(
            proxy=proxy_url,
            verify=ssl_context if self.config.upstream_ca else False,
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()
        if self.config.log_file and self.captured:
            self._save_log()

    async def post(
        self,
        url: str,
        json_data: Any = None,
        headers: dict = None,
        tool_name: str = None,
        payload: str = None,
    ) -> httpx.Response:
        """POST request routed through Burp proxy."""
        req_headers = {"Content-Type": "application/json", **(headers or {})}
        body_str = json.dumps(json_data) if json_data else None

        captured = ProxiedRequest(
            timestamp=time.time(),
            method="POST",
            url=url,
            headers=req_headers,
            body=body_str,
            tool_name=tool_name,
            payload_used=payload,
        )

        t0 = time.time()
        try:
            response = await self._client.post(url, content=body_str, headers=req_headers)
            captured.response_status = response.status_code
            captured.response_headers = dict(response.headers)
            captured.response_body = response.text
            captured.duration_ms = (time.time() - t0) * 1000
            self.captured.append(captured)
            return response
        except Exception as e:
            captured.response_body = f"ERROR: {e}"
            captured.duration_ms = (time.time() - t0) * 1000
            self.captured.append(captured)
            raise

    async def get(self, url: str, headers: dict = None) -> httpx.Response:
        """GET request routed through Burp proxy."""
        req_headers = headers or {}
        captured = ProxiedRequest(
            timestamp=time.time(),
            method="GET",
            url=url,
            headers=req_headers,
            body=None,
        )
        t0 = time.time()
        try:
            response = await self._client.get(url, headers=req_headers)
            captured.response_status = response.status_code
            captured.response_headers = dict(response.headers)
            captured.response_body = response.text
            captured.duration_ms = (time.time() - t0) * 1000
            self.captured.append(captured)
            return response
        except Exception as e:
            captured.response_body = f"ERROR: {e}"
            self.captured.append(captured)
            raise

    def _save_log(self):
        """Save captured traffic to log file in Burp-importable JSON format."""
        log_path = Path(self.config.log_file)
        entries = []
        for r in self.captured:
            entries.append({
                "timestamp": r.timestamp,
                "request": {
                    "method": r.method,
                    "url": r.url,
                    "headers": r.headers,
                    "body": r.body,
                },
                "response": {
                    "status": r.response_status,
                    "headers": r.response_headers,
                    "body": r.response_body,
                },
                "duration_ms": r.duration_ms,
                "mcploit": {
                    "tool_name": r.tool_name,
                    "payload_used": r.payload_used,
                },
            })
        with open(log_path, "w") as f:
            json.dump(entries, f, indent=2)
        console.print(f"[cyan]Burp traffic log saved → {log_path}[/cyan]")

    def print_summary(self):
        """Print captured traffic summary."""
        from rich.table import Table
        table = Table(title="Burp Proxy Traffic Capture", show_lines=True)
        table.add_column("#", style="dim")
        table.add_column("Method")
        table.add_column("URL", max_width=50)
        table.add_column("Status")
        table.add_column("Tool")
        table.add_column("ms", justify="right")

        for i, r in enumerate(self.captured, 1):
            status_style = "green" if r.response_status and r.response_status < 400 else "red"
            table.add_row(
                str(i),
                r.method,
                r.url,
                f"[{status_style}]{r.response_status or '?'}[/{status_style}]",
                r.tool_name or "-",
                f"{r.duration_ms:.0f}",
            )
        console.print(table)


class BurpSSECapture:
    """
    Captures SSE (Server-Sent Events) MCP traffic through Burp proxy.

    SSE streams are more complex - Burp can intercept them but needs
    specific configuration. This helper provides async SSE reading
    through the proxy.
    """

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.events: list[dict] = []

    async def stream_sse(self, url: str, on_event=None):
        """Read SSE stream through proxy, optionally calling on_event per message."""
        proxy_url = f"http://{self.config.host}:{self.config.port}"

        async with httpx.AsyncClient(
            proxy=proxy_url,
            verify=False,
            timeout=httpx.Timeout(60.0),
        ) as client:
            async with client.stream("GET", url, headers={"Accept": "text/event-stream"}) as response:
                async for line in response.aiter_lines():
                    if line.startswith("data:"):
                        data_str = line[5:].strip()
                        try:
                            event = json.loads(data_str)
                            self.events.append(event)
                            if on_event:
                                await on_event(event)
                        except json.JSONDecodeError:
                            pass


def create_burp_aware_transport(target_url: str, config: ProxyConfig):
    """
    Create a FastMCP transport that routes through Burp Suite.

    Returns a patched transport dict to inject into MCPClient.
    """
    return {
        "proxy_url": f"http://{config.host}:{config.port}",
        "target_url": target_url,
        "verify_ssl": config.verify_ssl,
    }
