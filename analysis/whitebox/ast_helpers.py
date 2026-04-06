"""
AST Helpers — Python source code analysis utilities.

Provides:
  - extract_tool_functions()   → @tool decorated functions with full metadata
  - extract_function_calls()   → all function calls within an AST node
  - get_dangerous_sinks()      → calls to eval/exec/subprocess/open etc.
  - param_reaches_sink()       → simple data-flow: does param reach a dangerous sink?
  - find_entry_points()        → auto-detect MCP server entry point files
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


DANGEROUS_SINK_NAMES = {
    # Shell / OS
    "eval", "exec", "system", "popen", "execl", "execle", "execlp",
    "execv", "execve", "execvp", "execvpe", "spawnl", "spawnle",
    # subprocess
    "run", "call", "check_call", "check_output", "Popen",
    # File I/O
    "open", "read_text", "write_text", "read_bytes", "write_bytes",
    # Python importlib
    "import_module", "__import__",
    # Deserialization
    "loads", "load",   # pickle, yaml, marshal
    # Network
    "urlopen", "urlretrieve", "get", "post", "request",
}

SHELL_SINK_MODULES = {"os", "subprocess", "commands", "pty"}


@dataclass
class ToolFunction:
    """Metadata extracted from an @tool decorated function."""
    name: str
    description: str           # From docstring or @tool(description=...)
    params: list[str]          # Parameter names (excl. self)
    param_types: dict          # {param: annotation_str}
    body_source: str           # Raw source of function body
    body_ast: Optional[ast.AST]
    file: str
    line_start: int
    line_end: int
    calls: list[str] = field(default_factory=list)       # All called names
    dangerous_calls: list[str] = field(default_factory=list)  # Dangerous sinks called
    has_shell_true: bool = False   # subprocess called with shell=True
    reaches_sink: dict = field(default_factory=dict)     # {param: [sink_names]}


@dataclass
class DangerousSink:
    """A detected dangerous function call."""
    func_name: str
    full_call: str     # e.g. "subprocess.run"
    line: int
    shell_true: bool = False
    arg_is_variable: bool = False   # True if arg is not a literal


def extract_tool_functions(filepath: str) -> list[ToolFunction]:
    """
    Parse a Python file and extract all @tool decorated functions with metadata.

    Handles both:
        @mcp.tool
        @mcp.tool(description="...")
        @tool
        @app.tool
    """
    try:
        source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, OSError):
        return []

    source_lines = source.splitlines()
    tools = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _has_tool_decorator(node):
            continue

        # Extract description from decorator or docstring
        desc = _extract_description(node, source_lines) or ""

        # Parameters
        args = node.args
        params = [a.arg for a in args.args if a.arg != "self"]
        params += [a.arg for a in (args.posonlyargs or [])]
        param_types = {}
        for a in args.args:
            if a.annotation:
                param_types[a.arg] = ast.unparse(a.annotation)

        # Body source
        body_start = node.body[0].lineno if node.body else node.lineno
        body_end = node.end_lineno or node.lineno
        body_source = "\n".join(source_lines[body_start - 1:body_end])

        # Function calls
        calls = extract_function_calls(node)
        dangerous = get_dangerous_sinks(node)
        has_shell_true = _has_shell_true(node)

        # Data flow: which params reach which sinks
        reaches = {}
        for p in params:
            sinks_reached = param_reaches_sink(node, p)
            if sinks_reached:
                reaches[p] = sinks_reached

        tf = ToolFunction(
            name=node.name,
            description=desc,
            params=params,
            param_types=param_types,
            body_source=body_source,
            body_ast=node,
            file=filepath,
            line_start=node.lineno,
            line_end=body_end,
            calls=calls,
            dangerous_calls=[s.full_call for s in dangerous],
            has_shell_true=has_shell_true,
            reaches_sink=reaches,
        )
        tools.append(tf)

    return tools


def extract_function_calls(node: ast.AST) -> list[str]:
    """Extract all function call names (including dotted) from an AST node."""
    calls = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _call_name(child)
            if name:
                calls.append(name)
    return list(dict.fromkeys(calls))  # deduplicate, preserve order


def get_dangerous_sinks(node: ast.AST) -> list[DangerousSink]:
    """Find all calls to dangerous sinks within an AST node."""
    sinks = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = _call_name(child)
        if not name:
            continue
        base = name.split(".")[-1]

        if base in DANGEROUS_SINK_NAMES:
            shell_true = _has_shell_true_in_call(child)
            arg_var = _call_has_variable_arg(child)
            sinks.append(DangerousSink(
                func_name=base,
                full_call=name,
                line=getattr(child, "lineno", 0),
                shell_true=shell_true,
                arg_is_variable=arg_var,
            ))
    return sinks


def param_reaches_sink(func_node: ast.AST, param_name: str) -> list[str]:
    """
    Simple taint analysis: does `param_name` flow into a dangerous sink?

    Returns list of sink names that receive the parameter (directly or via
    simple variable assignments — not full SSA, but catches the common case).
    """
    # Collect all names the param might flow through (assignments)
    tainted: set[str] = {param_name}
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            # taint = param or tainted_var
            if _rhs_uses(node.value, tainted):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)

    # Now check if any tainted name reaches a dangerous sink
    reached_sinks = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            sink_name = _call_name(node)
            if sink_name and sink_name.split(".")[-1] in DANGEROUS_SINK_NAMES:
                # Check if any arg is tainted
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    if _expr_uses(arg, tainted):
                        reached_sinks.append(sink_name)
                        break
    return list(dict.fromkeys(reached_sinks))


def find_entry_points(directory: str) -> list[str]:
    """
    Auto-detect MCP server entry point files in a directory.
    Delegates to the standalone entry_point_detector module.
    """
    from .entry_point_detector import find_entry_points as _detect
    return _detect(directory)


# ─────────────────────────────── Private helpers ─────────────────────────────

def _has_tool_decorator(node: ast.FunctionDef) -> bool:
    """Return True if a function has an @tool or @mcp.tool decorator."""
    for dec in node.decorator_list:
        dec_str = ast.unparse(dec).lower()
        if "tool" in dec_str or "mcp" in dec_str:
            return True
    return False


def _extract_description(node: ast.FunctionDef, source_lines: list[str]) -> str:
    """Extract description from decorator args or function docstring."""
    # Try decorator args: @tool(description="...")
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg in ("description", "desc"):
                    if isinstance(kw.value, ast.Constant):
                        return kw.value.value
    # Fall back to docstring
    if (node.body and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)):
        return str(node.body[0].value.value)
    return ""


def _call_name(call: ast.Call) -> Optional[str]:
    """Extract dotted name from a Call node."""
    try:
        return ast.unparse(call.func)
    except Exception:
        return None


def _has_shell_true(func_node: ast.AST) -> bool:
    """Check if any subprocess call in func_node uses shell=True."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call) and _has_shell_true_in_call(node):
            return True
    return False


def _has_shell_true_in_call(call: ast.Call) -> bool:
    """Check if a specific call has shell=True."""
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _call_has_variable_arg(call: ast.Call) -> bool:
    """Return True if any positional arg is a variable (not a literal)."""
    for arg in call.args:
        if isinstance(arg, ast.Name):
            return True
    return False


def _rhs_uses(node: ast.AST, names: set[str]) -> bool:
    """Return True if the expression node references any of the given names."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            return True
    return False


def _expr_uses(node: ast.AST, names: set[str]) -> bool:
    return _rhs_uses(node, names)
