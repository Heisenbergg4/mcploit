"""
Entry Point Detector — auto-discovers MCP server entry point files.

Searches a directory for files that instantiate or run an MCP server,
so the analysis engine knows exactly which files to run AST extraction on.

Detection heuristics (in priority order):
  1. Files importing FastMCP / mcp.server and calling .run() or if __name__
  2. Common entry-point names: server.py, main.py, app.py, __main__.py
  3. Files decorated with @mcp.tool, @app.tool indicating they ARE the server
  4. Files referencing MCP SDK: "from mcp import", "MCPServer(", "Server("
"""

import re
from pathlib import Path


# Patterns that strongly indicate an MCP server entry point
STRONG_ENTRY_PATTERNS = [
    r"FastMCP\s*\(",
    r"mcp\.server\.Server\s*\(",
    r"from mcp\.server import",
    r"from mcp import Server",
    r"MCPServer\s*\(",
    r"mcp = FastMCP",
    r"app = FastMCP",
    r"server = FastMCP",
    r'mcp\.run\s*\(',
    r'app\.run\s*\(',
    r'if __name__.*__main__',
]

# Weaker signals — file likely is part of an MCP server but maybe not the entry
WEAK_ENTRY_PATTERNS = [
    r"@mcp\.tool",
    r"@app\.tool",
    r"@server\.tool",
    r"from fastmcp import",
    r"import fastmcp",
    r"import mcp",
]

SKIP_DIRS = {"__pycache__", "node_modules", ".git", "venv", ".venv", "dist", "build", "test", "tests"}
PRIORITY_NAMES = {"server.py", "main.py", "app.py", "__main__.py", "index.py", "run.py"}


def find_entry_points(directory: str, max_results: int = 5) -> list[str]:
    """
    Auto-detect MCP server entry point files in a directory.

    Returns a ranked list of file paths, most likely entry point first.

    Args:
        directory: Root directory to search
        max_results: Maximum number of candidates to return

    Returns:
        List of absolute file paths ranked by likelihood of being the entry point
    """
    path = Path(directory)
    if not path.is_dir():
        if path.is_file():
            return [str(path)]
        return []

    candidates: list[tuple[int, str]] = []  # (score, filepath)

    for filepath in path.rglob("*.py"):
        # Skip unwanted directories
        if any(skip in filepath.parts for skip in SKIP_DIRS):
            continue

        score = _score_file(filepath)
        if score > 0:
            candidates.append((score, str(filepath)))

    # Sort by score descending, then by path length (prefer shallower files)
    candidates.sort(key=lambda x: (-x[0], len(x[1])))

    return [path for _, path in candidates[:max_results]]


def detect_framework(directory: str) -> str:
    """
    Detect which MCP framework the server uses.

    Returns: "fastmcp" | "official-sdk" | "mcp-framework" | "unknown"
    """
    path = Path(directory)
    sources = list(path.rglob("*.py"))[:20]

    framework_sigs = {
        "fastmcp": ["FastMCP", "from fastmcp", "import fastmcp"],
        "official-sdk": ["from mcp.server", "@server.list_tools", "from mcp import"],
        "mcp-framework": ["MCPServer", "from mcp_framework"],
    }

    for f in sources:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            for framework, sigs in framework_sigs.items():
                if any(sig in content for sig in sigs):
                    return framework
        except Exception:
            pass
    return "unknown"


def get_tool_files(directory: str) -> list[str]:
    """
    Find all files that contain @tool decorated functions.

    Useful when the tool definitions are spread across multiple files
    (common in larger MCP server projects).
    """
    tool_files = []
    path = Path(directory)

    for filepath in path.rglob("*.py"):
        if any(skip in filepath.parts for skip in SKIP_DIRS):
            continue
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            if re.search(r"@(mcp\.tool|app\.tool|server\.tool|tool)\b", content):
                tool_files.append(str(filepath))
        except Exception:
            pass

    return tool_files


def _score_file(filepath: Path) -> int:
    """Score a file on likelihood of being an MCP entry point."""
    score = 0
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0

    # Priority filename bonus
    if filepath.name in PRIORITY_NAMES:
        score += 5

    # Count strong pattern matches
    for pattern in STRONG_ENTRY_PATTERNS:
        if re.search(pattern, content):
            score += 3

    # Count weak pattern matches
    for pattern in WEAK_ENTRY_PATTERNS:
        if re.search(pattern, content):
            score += 1

    # Bonus for being in root or src/
    depth = len(filepath.relative_to(filepath.parent.parent).parts) if filepath.parent != filepath.parent.parent else 1
    if depth <= 2:
        score += 2

    return score
