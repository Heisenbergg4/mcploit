"""Rich console output utilities for MCPloit."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


def print_banner():
    """Print MCPloit banner."""
    banner = Text()
    banner.append("MCPloit", style="bold red")
    banner.append(" - MCP Security Testing Tool", style="dim")
    console.print(Panel(banner, border_style="red"))


def print_success(message: str):
    """Print success message."""
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str):
    """Print error message."""
    console.print(f"[red]✗[/red] {message}")


def print_warning(message: str):
    """Print warning message."""
    console.print(f"[yellow]![/yellow] {message}")


def print_info(message: str):
    """Print info message."""
    console.print(f"[blue]ℹ[/blue] {message}")


def print_server_info(server_name: str, version: str, capabilities: dict):
    """Print server information in a formatted panel."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Server", server_name)
    table.add_row("Version", version)

    cap_list = []
    if capabilities.get("tools"):
        cap_list.append("tools")
    if capabilities.get("resources"):
        cap_list.append("resources")
    if capabilities.get("prompts"):
        cap_list.append("prompts")

    table.add_row("Capabilities", ", ".join(cap_list) if cap_list else "none")

    console.print(Panel(table, title="[bold]Server Info[/bold]", border_style="green"))


def print_tools_table(tools: list):
    """Print tools in a formatted table."""
    if not tools:
        print_warning("No tools available")
        return

    table = Table(title="Available Tools", border_style="blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white", max_width=60)

    for i, tool in enumerate(tools, 1):
        desc = tool.description or ""
        if len(desc) > 60:
            desc = desc[:57] + "..."
        table.add_row(str(i), tool.name, desc)

    console.print(table)


def print_resources_table(resources: list):
    """Print resources in a formatted table."""
    if not resources:
        print_warning("No resources available")
        return

    table = Table(title="Available Resources", border_style="blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("URI", style="cyan")
    table.add_column("Name", style="white")

    for i, resource in enumerate(resources, 1):
        table.add_row(str(i), str(resource.uri), resource.name or "")

    console.print(table)


def print_prompts_table(prompts: list):
    """Print prompts in a formatted table."""
    if not prompts:
        print_warning("No prompts available")
        return

    table = Table(title="Available Prompts", border_style="blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white", max_width=60)

    for i, prompt in enumerate(prompts, 1):
        desc = prompt.description or ""
        if len(desc) > 60:
            desc = desc[:57] + "..."
        table.add_row(str(i), prompt.name, desc)

    console.print(table)
