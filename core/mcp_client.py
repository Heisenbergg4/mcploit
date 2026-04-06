"""MCPloit MCP Client wrapper with auto-transport detection."""

from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastmcp import Client
from fastmcp.client.transports import (
    PythonStdioTransport,
    NodeStdioTransport,
    SSETransport,
    StreamableHttpTransport,
)

from utils.logger import log
from utils.output import (
    print_success,
    print_error,
    print_info,
    print_server_info,
    print_tools_table,
    print_resources_table,
    print_prompts_table,
)


class TransportType(str, Enum):
    """Supported transport types."""

    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    AUTO = "auto"


class MCPClient:
    """Wrapper around fastmcp.Client with auto-transport detection."""

    def __init__(
        self,
        target: str,
        transport_type: TransportType = TransportType.AUTO,
        headers: dict[str, str] | None = None,
    ):
        """Initialize MCP client.

        Args:
            target: Connection target (URL or file path, can include arguments)
            transport_type: Transport type to use (auto-detected if not specified)
            headers: Extra HTTP headers (e.g. {"Authorization": "Bearer <token>"})
        """
        # Parse target for script path and optional arguments
        # Format: "script.py arg1 arg2" or just "script.py"
        self.target = target
        self.script_args: list[str] = []
        self.headers: dict[str, str] = headers or {}
        self._parse_target(target)
        self.transport_type = transport_type
        self._client: Client | None = None
        self._connected = False

    def _parse_target(self, target: str) -> None:
        """Parse target string to extract script path and arguments."""
        # Don't parse URLs
        if target.lower().startswith(("http://", "https://")):
            self.target = target
            return

        # Support npx / uvx / uv invocations:
        #   "npx -y @modelcontextprotocol/server-filesystem /allowed/path"
        #   "uvx mcp-server-git"
        parts = target.split()
        if parts and parts[0].lower() in ("npx", "uvx", "uv", "node", "python", "python3"):
            self.target = target   # keep the full invocation string; _create_transport handles it
            self.script_args = []
            return

        # For file paths, check if there are arguments
        # Split by spaces, but the first part ending in .py/.js/.mjs/.ts is the script
        if len(parts) > 1:
            for i, part in enumerate(parts):
                if part.endswith((".py", ".js", ".mjs", ".cjs", ".ts")):
                    self.target = part
                    self.script_args = parts[i + 1:]
                    return
        # No arguments found
        self.target = target
        self.script_args = []

    def _detect_transport(self) -> TransportType:
        """Auto-detect transport type from target string."""
        target_lower = self.target.lower()

        if target_lower.startswith(("http://", "https://")):
            parsed = urlparse(self.target)
            path_lower = parsed.path.lower()
            # /sse or /sse/ → explicit SSE; anything else → try StreamableHTTP first
            if path_lower.rstrip("/").endswith("/sse") or "/sse?" in path_lower:
                return TransportType.SSE
            return TransportType.HTTP

        # File-based stdio targets
        if target_lower.endswith(".py"):
            return TransportType.STDIO
        if target_lower.endswith((".js", ".mjs", ".cjs", ".ts")):
            return TransportType.STDIO

        # npx / uvx / uv / interpreter invocations
        first_word = target_lower.split()[0] if target_lower.split() else ""
        if first_word in ("npx", "uvx", "uv", "node", "python", "python3"):
            return TransportType.STDIO

        # Directory: look for a server entry point inside it
        target_path_obj = Path(self.target)
        if target_path_obj.is_dir():
            for candidate in ("server.py", "main.py", "app.py", "index.js", "index.mjs"):
                if (target_path_obj / candidate).exists():
                    return TransportType.STDIO
            py_files = list(target_path_obj.glob("*.py"))
            if py_files:
                return TransportType.STDIO
            js_files = list(target_path_obj.glob("*.js"))
            if js_files:
                return TransportType.STDIO
            raise ValueError(f"No server entry point found in directory: {self.target}")

        raise ValueError(f"Cannot auto-detect transport for target: {self.target}")

    def _create_transport(self):
        """Create appropriate transport based on type and target."""
        if self.transport_type == TransportType.AUTO:
            self.transport_type = self._detect_transport()

        log.debug(f"Using transport: {self.transport_type.value}")

        if self.transport_type == TransportType.SSE:
            return SSETransport(url=self.target, headers=self.headers or None)

        if self.transport_type == TransportType.HTTP:
            return StreamableHttpTransport(url=self.target, headers=self.headers or None)

        if self.transport_type == TransportType.STDIO:
            # ── npx / uvx / interpreter invocations ──────────────────────
            parts = self.target.split()
            first = parts[0].lower() if parts else ""

            if first in ("npx", "node"):
                # e.g. "npx -y @modelcontextprotocol/server-filesystem /path"
                return NodeStdioTransport(
                    script_path=parts[0],
                    args=parts[1:] or None,
                    # env=None → inherit parent environment (PATH, NODE_PATH, etc.)
                )
            if first in ("python", "python3"):
                # e.g. "python path/to/server.py /workspace"
                # parts[0] is the interpreter — parts[1] is the actual .py file
                if len(parts) < 2:
                    raise ValueError("Expected: python <script.py> [args...]")
                return PythonStdioTransport(
                    script_path=parts[1],
                    args=parts[2:] or None,
                )
            if first in ("uvx", "uv"):
                return PythonStdioTransport(
                    script_path=parts[0],
                    args=parts[1:] or None,
                    # env=None → inherit parent environment
                )

            # ── File-path based invocations ───────────────────────────────
            target_path = Path(self.target)
            if not target_path.exists():
                raise FileNotFoundError(f"Server file not found: {self.target}")

            # Resolve directory → entry point file
            if target_path.is_dir():
                for candidate in ("server.py", "main.py", "app.py", "index.js", "index.mjs"):
                    if (target_path / candidate).exists():
                        target_path = target_path / candidate
                        self.target = str(target_path)
                        break
                else:
                    py_files = sorted(target_path.glob("*.py"))
                    js_files = sorted(target_path.glob("*.js"))
                    if py_files:
                        target_path = py_files[0]
                        self.target = str(target_path)
                    elif js_files:
                        target_path = js_files[0]
                        self.target = str(target_path)
                    else:
                        raise ValueError(f"No server entry point found in directory: {self.target}")

            if self.target.endswith(".py"):
                return PythonStdioTransport(
                    script_path=str(target_path.resolve()),
                    args=self.script_args if self.script_args else None,
                    # env=None → inherit parent environment; env={} would blank PATH/PYTHONPATH
                )
            elif self.target.endswith((".js", ".mjs", ".cjs")):
                return NodeStdioTransport(
                    script_path=str(target_path.resolve()),
                    args=self.script_args if self.script_args else None,
                )
            elif self.target.endswith(".ts"):
                # Assume ts-node is available; fall back to node if not
                return NodeStdioTransport(
                    script_path="ts-node",
                    args=[str(target_path.resolve())] + (self.script_args or []),
                )
            else:
                raise ValueError(f"Unsupported file type: {self.target}")

        raise ValueError(f"Unknown transport type: {self.transport_type}")

    async def connect(self) -> bool:
        """Establish connection to MCP server.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            transport = self._create_transport()
            self._client = Client(transport)

            print_info(f"Connecting to {self.target} via {self.transport_type.value}...")

            await self._client.__aenter__()
            self._connected = True

            init_result = self._client.initialize_result
            if init_result and init_result.serverInfo:
                server_name = init_result.serverInfo.name or "Unknown"
                version = init_result.serverInfo.version or "Unknown"

                caps = {}
                if init_result.capabilities:
                    caps = {
                        "tools": init_result.capabilities.tools is not None,
                        "resources": init_result.capabilities.resources is not None,
                        "prompts": init_result.capabilities.prompts is not None,
                    }

                print_success("Connected successfully!")
                print_server_info(server_name, version, caps)
            else:
                print_success("Connected (no server info available)")

            return True

        except Exception as e:
            print_error(f"Connection failed: {e}")
            log.exception("Connection error")
            self._connected = False
            return False

    async def disconnect(self):
        """Close connection to MCP server."""
        if self._client and self._connected:
            try:
                await self._client.__aexit__(None, None, None)
                print_info("Disconnected from server")
            except Exception as e:
                log.warning(f"Error during disconnect: {e}")
            finally:
                self._connected = False
                self._client = None

    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected and self._client is not None

    async def list_tools(self) -> list:
        """List available tools on the server."""
        if not self.is_connected:
            raise RuntimeError("Not connected to server")
        return await self._client.list_tools()

    async def list_resources(self) -> list:
        """List available resources on the server."""
        if not self.is_connected:
            raise RuntimeError("Not connected to server")
        return await self._client.list_resources()

    async def list_prompts(self) -> list:
        """List available prompts on the server."""
        if not self.is_connected:
            raise RuntimeError("Not connected to server")
        return await self._client.list_prompts()

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None):
        """Call a tool on the server.

        Args:
            name: Tool name
            arguments: Tool arguments

        Returns:
            Tool result
        """
        if not self.is_connected:
            raise RuntimeError("Not connected to server")
        return await self._client.call_tool(name, arguments or {})

    async def read_resource(self, uri: str):
        """Read a resource from the server.

        Args:
            uri: Resource URI

        Returns:
            Resource content
        """
        if not self.is_connected:
            raise RuntimeError("Not connected to server")
        return await self._client.read_resource(uri)

    async def get_prompt(self, name: str, arguments: dict[str, Any] | None = None):
        """Get a rendered prompt from the server.

        Args:
            name: Prompt name
            arguments: Prompt arguments

        Returns:
            Rendered prompt messages
        """
        if not self.is_connected:
            raise RuntimeError("Not connected to server")
        return await self._client.get_prompt(name, arguments or {})

    async def enumerate(self):
        """Enumerate all server capabilities and print them."""
        if not self.is_connected:
            raise RuntimeError("Not connected to server")

        try:
            tools = await self.list_tools()
            print_tools_table(tools)
        except Exception as e:
            log.debug(f"Could not list tools: {e}")

        try:
            resources = await self.list_resources()
            print_resources_table(resources)
        except Exception as e:
            log.debug(f"Could not list resources: {e}")

        try:
            prompts = await self.list_prompts()
            print_prompts_table(prompts)
        except Exception as e:
            log.debug(f"Could not list prompts: {e}")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
