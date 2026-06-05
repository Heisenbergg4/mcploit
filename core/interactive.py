"""Interactive MCP exploration shell."""

import asyncio
import json
import os
import shlex
from typing import Callable

# readline gives us line editing, ↑/↓ history traversal and tab-completion for
# free on the platform's input(). It ships with CPython on Linux/macOS; on
# Windows it lives in the optional `pyreadline3` package. If neither is present
# the shell still works — it just loses history/completion niceties.
try:
    import readline
except ImportError:  # pragma: no cover - Windows without pyreadline3
    try:
        import pyreadline3 as readline  # type: ignore
    except ImportError:
        readline = None

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from utils.logger import log
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

        # ── Tab-completion state ────────────────────────────────────────────
        # Names are cached once at startup (and after the relevant list-*
        # commands) so the synchronous readline completer has data to offer
        # without needing to make async calls mid-keystroke.
        self._tool_names: list[str] = []
        self._tools: list = []
        self._resource_uris: list[str] = []
        self._prompt_names: list[str] = []
        self._completion_matches: list[str] = []
        self._raw_line: str = ""

        # Persist ↑/↓ history across sessions (best-effort).
        self._history_file = os.path.join(
            os.path.expanduser("~"), ".mcploit_history"
        )

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
        if readline is not None:
            banner.append("\n", style="dim")
            banner.append("↑/↓", style="cyan")
            banner.append(" history  ·  ", style="dim")
            banner.append("Tab", style="cyan")
            banner.append(" to complete commands, tools & resources", style="dim")
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
             "call-tool <name> <val> | key=val | '{\"k\":\"v\"}'"),
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
    def _parse_tool_args(raw: str, param_names: list[str] | None = None) -> dict:
        """Parse a tool call's raw argument string.

        ``raw`` is the portion of the command line *after the tool name*, passed
        verbatim — it is NOT shlex-tokenised — so payloads keep their exact
        spacing, quotes, backslashes and shell metacharacters intact. This is
        what lets values like ``whoami;cat  flag.txt`` or ``echo \\$HOME`` reach
        the server unchanged.

        Formats, tried in order:
          1. JSON object   : {"key": "val"}
          2. key=value     : key1=val1 key2=val2   (whitespace-separated)
          3. positional    : mapped onto the tool's parameters in declaration
                             order. A single-parameter tool receives the ENTIRE
                             raw string as its one value.

        ``param_names`` is the ordered list of the tool's parameter names (from
        its input schema). It enables positional mapping and makes key=value
        parsing stricter, so a value that itself contains '=' (e.g. a URL with a
        query string) isn't mistaken for a key=value pair.

        Returns the parsed dict, or raises ValueError with a helpful message.
        """
        raw = raw.strip()
        if not raw:
            return {}

        # Optionally peel ONE layer of wrapping quotes — but only when they truly
        # wrap the whole string (matching outer quotes with no same-quote inside).
        # This lets users quote for clarity without changing the value, while
        # leaving payloads like  'a' && 'b'  untouched.
        unwrapped = raw
        if (
            len(raw) >= 2
            and raw[0] == raw[-1]
            and raw[0] in ("'", '"')
            and raw[0] not in raw[1:-1]
        ):
            unwrapped = raw[1:-1]

        # 1. JSON object ────────────────────────────────────────────────────
        try:
            parsed = json.loads(unwrapped)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        def _auto_type(value: str):
            """JSON-decode a scalar (int/float/bool/null), else keep as string."""
            try:
                return json.loads(value)
            except (json.JSONDecodeError, ValueError):
                return value

        known = set(param_names or [])
        tokens = unwrapped.split()

        # 2. key=value ───────────────────────────────────────────────────────
        # A token counts as key=value only if it contains '=' and — when we know
        # the schema — its key is an actual parameter. That guard stops values
        # like "http://host/path?a=b" from being split into {"http://host/path?a": "b"}.
        def _is_kv(token: str) -> bool:
            if "=" not in token:
                return False
            key = token.partition("=")[0]
            return not known or key in known

        if tokens and all(_is_kv(t) for t in tokens):
            return {t.partition("=")[0]: _auto_type(t.partition("=")[2]) for t in tokens}

        # 3. positional ───────────────────────────────────────────────────────
        if param_names:
            # Single-parameter tool: the entire raw value is that one argument,
            # verbatim — original spacing and metacharacters preserved.
            if len(param_names) == 1:
                return {param_names[0]: _auto_type(unwrapped)}
            # Multi-parameter tool: one whitespace-separated token per parameter.
            if len(tokens) <= len(param_names):
                return {name: _auto_type(tok) for name, tok in zip(param_names, tokens)}

        raise ValueError(
            "Cannot parse arguments.\n"
            "  positional : call-tool <name> <value> [value2 ...]\n"
            "  key=value  : call-tool <name> key=value key2=value2\n"
            "  JSON       : call-tool <name> '{\"key\": \"value\"}'\n"
            "  (a single-parameter tool takes the whole line as its value; quote "
            "only when you want exact whitespace preserved)"
        )

    def _tool_schema(self, tool_name: str) -> dict | None:
        """Return a cached tool's input schema (or None if unknown)."""
        for tool in getattr(self, "_tools", []):
            if tool.name == tool_name:
                return getattr(tool, "inputSchema", None)
        return None

    def _raw_args_after_tool(self, tool_name: str, fallback: list[str]) -> str:
        """Recover the argument substring after the tool name, un-tokenised.

        Uses the original input line (``self._raw_line``) so the value isn't
        mangled by the shlex pass in ``_parse_command``. Splits only off the
        leading command word and the tool-name token, both of which are plain
        identifiers, then hands back everything after them verbatim.

        Falls back to re-joining the already-split ``fallback`` tokens when the
        raw line isn't available or doesn't line up (e.g. programmatic calls).
        """
        line = (getattr(self, "_raw_line", "") or "").strip()
        # Strip the command word, then the tool-name token.
        after_cmd = line.split(None, 1)
        if len(after_cmd) == 2:
            after_tool = after_cmd[1].split(None, 1)
            if after_tool and after_tool[0] == tool_name:
                return after_tool[1] if len(after_tool) == 2 else ""
        return " ".join(fallback)

    async def _cmd_call_tool(self, args: list[str]):
        """Call a tool with arguments."""
        if not args:
            print_error("Usage: call-tool <name> [args]")
            print_info("  positional : call-tool fetch_price_data http://host/api")
            print_info("  kv         : call-tool fetch_price_data url=http://host/api")
            print_info("  JSON       : call-tool fetch_price_data '{\"url\": \"http://host/api\"}'")
            return

        tool_name = args[0]
        tool_args = {}

        # Pull the parameter order from the tool's schema so a bare positional
        # value (e.g. just the URL) maps onto the right parameter name.
        param_names: list[str] = []
        schema = self._tool_schema(tool_name)
        if schema and isinstance(schema.get("properties"), dict):
            param_names = list(schema["properties"].keys())

        if len(args) > 1:
            # Parse the value from the *raw* line, not the shlex-split tokens, so
            # spaces / quotes / backslashes / metacharacters survive untouched.
            raw_args = self._raw_args_after_tool(tool_name, args[1:])
            try:
                tool_args = self._parse_tool_args(raw_args, param_names)
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

    # ──────────────────────────────────────────────────────────────────────
    # Line editing: history (↑/↓) and tab-completion
    # ──────────────────────────────────────────────────────────────────────
    def _setup_readline(self):
        """Enable ↑/↓ history traversal and Tab completion for input().

        Safe no-op when no readline implementation is available.
        """
        if readline is None:
            return
        try:
            # Treat only whitespace as a word boundary. The default delim set
            # includes '-', ':' and '/', which would wrongly split tokens like
            # "list-tools" or "resource://logs" mid-word during completion.
            readline.set_completer_delims(" \t\n")
            readline.set_completer(self._completer)

            # GNU readline and the libedit shim (common on macOS) use different
            # syntax to bind the Tab key to completion.
            if "libedit" in (getattr(readline, "__doc__", "") or ""):
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")

            readline.set_history_length(1000)
            try:
                readline.read_history_file(self._history_file)
            except (FileNotFoundError, OSError):
                pass
        except Exception as e:  # pragma: no cover - defensive
            log.debug(f"readline setup skipped: {e}")

    def _teardown_readline(self):
        """Persist history to disk on exit (best-effort)."""
        if readline is None:
            return
        try:
            readline.write_history_file(self._history_file)
        except Exception as e:  # pragma: no cover - defensive
            log.debug(f"Could not write history file: {e}")

    def _completer(self, text: str, state: int):
        """readline completion callback.

        Called repeatedly with increasing ``state`` until it returns None.
        We compute the full candidate list on state 0 and index into it after.
        """
        if readline is None:
            return None
        try:
            if state == 0:
                self._completion_matches = self._compute_completions(text)
            if 0 <= state < len(self._completion_matches):
                return self._completion_matches[state]
            return None
        except Exception:  # pragma: no cover - never let completion crash input
            return None

    def _compute_completions(self, text: str) -> list[str]:
        """Return completion candidates for the word currently being typed.

        - First word  → command names (and aliases).
        - call-tool / ct  <TAB>   → live tool names.
        - read-resource / rr <TAB> → live resource URIs.
        - get-prompt / gp <TAB>   → live prompt names.
        """
        buffer = readline.get_line_buffer()
        begidx = readline.get_begidx()
        # Tokens that appear *before* the word being completed.
        preceding = buffer[:begidx].split()

        if not preceding:
            # Completing the command itself.
            pool = sorted(self.commands.keys())
        elif len(preceding) == 1:
            # Completing the first argument right after the command.
            cmd = preceding[0].lower()
            if cmd in ("call-tool", "ct"):
                pool = self._tool_names
            elif cmd in ("read-resource", "rr"):
                pool = self._resource_uris
            elif cmd in ("get-prompt", "gp"):
                pool = self._prompt_names
            else:
                pool = []
        else:
            # Deeper arguments (JSON / key=value) — nothing sensible to offer.
            pool = []

        return [c for c in pool if c.startswith(text)]

    async def _refresh_completion_cache(self):
        """Pre-fetch tool/resource/prompt names for tab-completion.

        Each lookup is isolated so a server that lacks one capability (or errors
        on it) doesn't wipe out completion for the others.
        """
        try:
            tools = await self.client.list_tools()
            self._tools = tools
            self._tool_names = [t.name for t in tools]
        except Exception:
            self._tools = []
            self._tool_names = []
        try:
            self._resource_uris = [
                str(r.uri) for r in await self.client.list_resources()
            ]
        except Exception:
            self._resource_uris = []
        try:
            self._prompt_names = [p.name for p in await self.client.list_prompts()]
        except Exception:
            self._prompt_names = []

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
        self._setup_readline()
        # Warm the completion cache so Tab works from the first keystroke.
        await self._refresh_completion_cache()

        try:
            while self.running:
                try:
                    # _async_input runs input() in a thread executor so we don't
                    # block the asyncio event loop (plain Prompt.ask / input() would).
                    # readline hooks into that input() call, giving ↑/↓ history
                    # and Tab completion transparently.
                    line = await _async_input("mcploit")

                    if not line.strip():
                        continue

                    # Stash the verbatim line so call-tool can recover its
                    # argument string without shlex mangling (see _cmd_call_tool).
                    self._raw_line = line

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
        finally:
            self._teardown_readline()

        console.print()
