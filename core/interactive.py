"""Interactive MCP exploration shell."""

import asyncio
import json
import shlex
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from utils.output import print_success, print_error, print_warning, print_info


console = Console()


async def _async_input(prompt: str) -> str:
    """Non-blocking async input that doesn't stall the event loop.

    rich.Prompt.ask() calls input() synchronously which blocks the entire
    asyncio event loop — this wrapper runs it in a thread executor instead.
    """
    loop = asyncio.get_running_loop()
    # Print prompt manually (rich markup stripped for raw input)
    plain_prompt = prompt.replace("[bold red]", "").replace("[/bold red]", "")
    return await loop.run_in_executor(None, lambda: input(f"{plain_prompt}> "))


class InteractiveShell:
    """Interactive shell for MCP server exploration."""

    def __init__(self, client):
        """Initialize interactive shell.

        Args:
            client: Connected MCPClient instance
        """
        self.client = client
        self.running = False
        self.history = []
        self.commands: dict[str, Callable] = {
            # Full names
            "help": self._cmd_help,
            "list-tools": self._cmd_list_tools,
            "list-resources": self._cmd_list_resources,
            "list-prompts": self._cmd_list_prompts,
            "call-tool": self._cmd_call_tool,
            "read-resource": self._cmd_read_resource,
            "get-prompt": self._cmd_get_prompt,
            "info": self._cmd_info,
            "history": self._cmd_history,
            "clear": self._cmd_clear,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            # Short aliases
            "lt": self._cmd_list_tools,
            "lr": self._cmd_list_resources,
            "lp": self._cmd_list_prompts,
            "ct": self._cmd_call_tool,
            "rr": self._cmd_read_resource,
            "gp": self._cmd_get_prompt,
            "h": self._cmd_help,
            "q": self._cmd_exit,
        }

    def _print_banner(self):
        """Print interactive shell banner."""
        banner = Text()
        banner.append("MCPloit Interactive Shell\n", style="bold red")
        banner.append("Type ", style="dim")
        banner.append("help", style="cyan")
        banner.append(" for available commands, ", style="dim")
        banner.append("exit", style="cyan")
        banner.append(" to quit", style="dim")
        console.print(Panel(banner, border_style="red"))

    async def _cmd_help(self, args: list[str]):
        """Show help information."""
        table = Table(title="Available Commands", border_style="cyan")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Usage", style="yellow")

        commands = [
            ("list-tools   [lt]", "List all available tools", "list-tools"),
            ("list-resources [lr]", "List all available resources", "list-resources"),
            ("list-prompts  [lp]", "List all available prompts", "list-prompts"),
            ("call-tool    [ct]", "Call a tool with arguments",
             "call-tool <name> [key=val ...]'{\"key\":\"val\"}'"),
            ("read-resource [rr]", "Read a resource by URI", "read-resource <uri>"),
            ("get-prompt   [gp]", "Get a rendered prompt", "get-prompt <name> [key=val]"),
            ("info", "Show server information", "info"),
            ("history", "Show command history", "history"),
            ("clear", "Clear the screen", "clear"),
            ("exit / q", "Exit interactive shell", "exit"),
        ]

        for cmd, desc, usage in commands:
            table.add_row(cmd, desc, usage)

        console.print(table)

    async def _cmd_list_tools(self, args: list[str]):
        """List all tools."""
        try:
            tools = await self.client.list_tools()
            if not tools:
                print_warning("No tools available")
                return

            table = Table(title=f"Tools ({len(tools)})", border_style="cyan", show_lines=True)
            table.add_column("#", style="dim", width=3)
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            table.add_column("Parameters", style="yellow")

            for i, tool in enumerate(tools, 1):
                desc = tool.description or "-"

                params = []
                if tool.inputSchema and "properties" in tool.inputSchema:
                    required = tool.inputSchema.get("required", [])
                    for name, info in tool.inputSchema["properties"].items():
                        param_type = info.get("type", "any")
                        req_marker = "*" if name in required else ""
                        params.append(f"{name}{req_marker}: {param_type}")

                params_str = "\n".join(params) if params else "-"
                table.add_row(str(i), tool.name, desc, params_str)

            console.print(table)

        except Exception as e:
            print_error(f"Failed to list tools: {e}")

    async def _cmd_list_resources(self, args: list[str]):
        """List all resources."""
        try:
            resources = await self.client.list_resources()
            if not resources:
                print_warning("No resources available")
                return

            table = Table(title=f"Resources ({len(resources)})", border_style="green", show_lines=True)
            table.add_column("#", style="dim", width=3)
            table.add_column("URI", style="green")
            table.add_column("Name", style="white")
            table.add_column("MIME Type", style="yellow")

            for i, resource in enumerate(resources, 1):
                table.add_row(
                    str(i),
                    str(resource.uri),
                    resource.name or "-",
                    resource.mimeType or "-"
                )

            console.print(table)

        except Exception as e:
            print_error(f"Failed to list resources: {e}")

    async def _cmd_list_prompts(self, args: list[str]):
        """List all prompts."""
        try:
            prompts = await self.client.list_prompts()
            if not prompts:
                print_warning("No prompts available")
                return

            table = Table(title=f"Prompts ({len(prompts)})", border_style="magenta", show_lines=True)
            table.add_column("#", style="dim", width=3)
            table.add_column("Name", style="magenta")
            table.add_column("Description", style="white")
            table.add_column("Arguments", style="yellow")

            for i, prompt in enumerate(prompts, 1):
                args_list = []
                if prompt.arguments:
                    for arg in prompt.arguments:
                        req = "*" if arg.required else ""
                        args_list.append(f"{arg.name}{req}")

                table.add_row(
                    str(i),
                    prompt.name,
                    prompt.description or "-",
                    ", ".join(args_list) if args_list else "-"
                )

            console.print(table)

        except Exception as e:
            print_error(f"Failed to list prompts: {e}")

    @staticmethod
    def _parse_tool_args(args: list[str]) -> dict:
        """Parse tool arguments from CLI tokens.

        Accepts two formats:
          1. JSON string  : {"key": "val"}   (must be one quoted token on Windows,
                            or the last N unquoted tokens that together form valid JSON)
          2. key=value pairs: key1=val1 key2=val2   (values auto-typed: int/float/bool/str)

        Returns parsed dict or raises ValueError with a helpful message.
        """
        if not args:
            return {}

        # Try joining all tokens as JSON first
        joined = " ".join(args).strip()
        # Strip wrapping single-quotes that Windows cmd users sometimes add
        if joined.startswith("'") and joined.endswith("'"):
            joined = joined[1:-1]
        try:
            parsed = json.loads(joined)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        # Try key=value style
        if all("=" in a for a in args):
            result: dict = {}
            for a in args:
                k, _, v = a.partition("=")
                # Auto-type the value
                for converter in (json.loads,):
                    try:
                        result[k] = converter(v)
                        break
                    except (json.JSONDecodeError, ValueError):
                        result[k] = v
            return result

        raise ValueError(
            "Cannot parse arguments.\n"
            "  JSON style  : call-tool <name> '{\"key\": \"value\"}'\n"
            "  key=value   : call-tool <name> key=value key2=value2"
        )

    async def _cmd_call_tool(self, args: list[str]):
        """Call a tool with arguments."""
        if not args:
            print_error("Usage: call-tool <name> [args]")
            print_info("  JSON   : call-tool get_user '{\"user_id\": \"123\"}'")
            print_info("  kv     : call-tool get_user user_id=123")
            return

        tool_name = args[0]
        tool_args = {}

        if len(args) > 1:
            try:
                tool_args = self._parse_tool_args(args[1:])
            except ValueError as e:
                print_error(str(e))
                return

        try:
            print_info(f"Calling tool: {tool_name}")
            result = await self.client.call_tool(tool_name, tool_args)

            console.print()
            console.print(Panel("[bold]Tool Result[/bold]", border_style="green"))

            # fastmcp CallToolResult has .content (list of TextContent/BlobContent)
            # and .is_error — there is no .data attribute
            if hasattr(result, 'content') and result.content:
                for content in result.content:
                    if hasattr(content, 'text'):
                        # Pretty-print JSON if parseable, otherwise plain text
                        try:
                            parsed = json.loads(content.text)
                            syntax = Syntax(
                                json.dumps(parsed, indent=2),
                                "json",
                                theme="monokai"
                            )
                            console.print(syntax)
                        except (json.JSONDecodeError, TypeError):
                            console.print(content.text)
                    elif hasattr(content, 'blob'):
                        blob = content.blob
                        console.print(f"  [Binary data: {len(blob)} bytes]")
                        preview = blob[:64]
                        hex_str = " ".join(f"{b:02x}" for b in preview)
                        console.print(f"  [dim]Hex: {hex_str}{'...' if len(blob) > 64 else ''}[/dim]")
            else:
                console.print(f"  [dim]{result}[/dim]")

            # Check for errors
            if hasattr(result, 'is_error') and result.is_error:
                print_warning("Tool returned an error flag")
            else:
                print_success("Tool call completed")

        except Exception as e:
            print_error(f"Tool call failed: {e}")

    async def _cmd_read_resource(self, args: list[str]):
        """Read a resource by URI."""
        if not args:
            print_error("Usage: read-resource <uri>")
            print_info("Example: read-resource file:///etc/passwd")
            return

        uri = args[0]

        try:
            print_info(f"Reading resource: {uri}")
            content = await self.client.read_resource(uri)

            console.print()
            console.print(Panel(f"[bold]Resource: {uri}[/bold]", border_style="green"))

            for item in content:
                if hasattr(item, 'text'):
                    # Try to parse as JSON for pretty printing
                    try:
                        parsed = json.loads(item.text)
                        syntax = Syntax(
                            json.dumps(parsed, indent=2),
                            "json",
                            theme="monokai"
                        )
                        console.print(syntax)
                    except (json.JSONDecodeError, TypeError):
                        console.print(item.text)
                elif hasattr(item, 'blob'):
                    console.print(f"[Binary data: {len(item.blob)} bytes]")
                    # Show hex preview
                    preview = item.blob[:64]
                    hex_str = " ".join(f"{b:02x}" for b in preview)
                    console.print(f"[dim]Hex preview: {hex_str}...[/dim]")

            print_success("Resource read completed")

        except Exception as e:
            print_error(f"Failed to read resource: {e}")

    async def _cmd_get_prompt(self, args: list[str]):
        """Get a rendered prompt."""
        if not args:
            print_error("Usage: get-prompt <name> [json_args]")
            print_info("Example: get-prompt greeting {\"name\": \"World\"}")
            return

        prompt_name = args[0]
        prompt_args = {}

        if len(args) > 1:
            json_str = " ".join(args[1:])
            try:
                prompt_args = json.loads(json_str)
            except json.JSONDecodeError as e:
                print_error(f"Invalid JSON arguments: {e}")
                return

        try:
            print_info(f"Getting prompt: {prompt_name}")
            result = await self.client.get_prompt(prompt_name, prompt_args)

            console.print()
            console.print(Panel(f"[bold]Prompt: {prompt_name}[/bold]", border_style="magenta"))

            if hasattr(result, 'messages') and result.messages:
                for i, message in enumerate(result.messages):
                    role = message.role if hasattr(message, 'role') else 'unknown'
                    role_style = "cyan" if role == "user" else "green" if role == "assistant" else "yellow"

                    console.print(f"\n[{role_style}][{role}][/{role_style}]")

                    if hasattr(message.content, 'text'):
                        console.print(message.content.text)
                    else:
                        console.print(str(message.content))

            print_success("Prompt retrieved")

        except Exception as e:
            print_error(f"Failed to get prompt: {e}")

    async def _cmd_info(self, args: list[str]):
        """Show server information."""
        try:
            # Access initialize_result through the internal client — wrapped in
            # try/except so version differences in the MCP SDK don't crash the shell.
            internal = getattr(self.client, '_client', None)
            init = getattr(internal, 'initialize_result', None) if internal else None

            if not init:
                print_warning("No server info available (not connected or SDK version mismatch)")
                return

            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")

            if init.serverInfo:
                table.add_row("Server", init.serverInfo.name or "Unknown")
                table.add_row("Version", init.serverInfo.version or "Unknown")

            if init.capabilities:
                caps = []
                if init.capabilities.tools:
                    caps.append("tools")
                if init.capabilities.resources:
                    caps.append("resources")
                if init.capabilities.prompts:
                    caps.append("prompts")
                table.add_row("Capabilities", ", ".join(caps) if caps else "none")

            if init.instructions:
                table.add_row("Instructions", init.instructions[:100] + "..." if len(init.instructions) > 100 else init.instructions)

            console.print(Panel(table, title="Server Info", border_style="blue"))

        except Exception as e:
            print_error(f"Could not retrieve server info: {e}")

    async def _cmd_history(self, args: list[str]):
        """Show command history."""
        if not self.history:
            print_info("No command history")
            return

        console.print("[bold]Command History:[/bold]")
        for i, cmd in enumerate(self.history, 1):
            console.print(f"  {i}. {cmd}")

    async def _cmd_clear(self, args: list[str]):
        """Clear the screen."""
        console.clear()
        self._print_banner()

    async def _cmd_exit(self, args: list[str]):
        """Exit the shell."""
        self.running = False
        print_info("Exiting interactive shell...")

    def _parse_command(self, line: str) -> tuple[str, list[str]]:
        """Parse command line into command and arguments.

        Args:
            line: Input line

        Returns:
            Tuple of (command, arguments)
        """
        line = line.strip()
        if not line:
            return "", []

        try:
            parts = shlex.split(line)
        except ValueError:
            # Handle unmatched quotes
            parts = line.split()

        if not parts:
            return "", []

        return parts[0].lower(), parts[1:]

    async def run(self):
        """Run the interactive shell."""
        self.running = True
        self._print_banner()

        while self.running:
            try:
                # _async_input runs input() in a thread executor so we don't
                # block the asyncio event loop (plain Prompt.ask / input() would).
                line = await _async_input("mcploit")

                if not line.strip():
                    continue

                # Parse command
                cmd, args = self._parse_command(line)

                if not cmd:
                    continue

                # Add to history
                self.history.append(line)

                # Execute command
                if cmd in self.commands:
                    await self.commands[cmd](args)
                else:
                    print_error(f"Unknown command: {cmd}")
                    print_info("Type 'help' or 'h' for available commands")

            except KeyboardInterrupt:
                console.print()
                print_info("Use 'exit' or 'q' to quit")
            except EOFError:
                # Ctrl+D / pipe closed
                self.running = False
                break
            except Exception as e:
                print_error(f"Error: {e}")

        console.print()
