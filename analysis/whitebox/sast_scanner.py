"""
Regex-Based Source Code Vulnerability Analysis (SAST) Tool.

Performs static analysis on MCP server source code using regex patterns
to detect dangerous sinks, hardcoded secrets, MCP anti-patterns, and
injection vectors without executing the code.

Supports language-aware scanning (Python vs JS/TS) and filters out
common false-positive patterns like test files, imports, and comments.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

console = Console()

# ─────────────────────────────────────────────────
# Language targeting constants
# ─────────────────────────────────────────────────
PYTHON_EXTS = {".py"}
JS_TS_EXTS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
ALL_EXTS = PYTHON_EXTS | JS_TS_EXTS
TEST_PATTERNS = re.compile(
    r'([\\/]tests?[\\/]'           # any file under test/ or tests/ directory
    r'|[\\/]__tests__[\\/]'        # __tests__ directory
    r'|[\\/]fixtures?[\\/]'        # fixture directories
    r'|[\\/]mocks?[\\/]'           # mock directories
    r'|[\\/]test[_\-]'             # files starting with test- or test_ in any dir
    r'|[_\-]test\.'               # files ending with _test. or -test.
    r'|\.test\.'                  # files with .test. in name
    r'|\.spec\.'                  # files with .spec. in name
    r'|[\\/]validate[_\-]'        # validation scripts (e.g., validate-api.js)
    r')',
    re.IGNORECASE,
)


@dataclass
class SASTFinding:
    """A single finding from source code analysis."""
    rule_id: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    description: str
    file: str
    line: int
    column: int = 0
    code_snippet: str = ""
    recommendation: str = ""
    category: str = ""      # rce, secrets, injection, path_traversal, ssrf, etc.
    cve: str = ""
    confidence: str = "HIGH"

    def __str__(self):
        return f"[{self.severity}] {self.rule_id}: {self.title} @ {self.file}:{self.line}"


# ─────────────────────────────────────────────────
# Rule definitions (v2 — language-aware, reduced FP)
#
# Each rule is a dict with keys:
#   id, severity, title, pattern, category, recommendation, cve,
#   langs       — set of extensions to apply this rule to (default: ALL_EXTS)
#   exclude     — regex; if matched against the LINE, skip this hit
#   test_only   — if True, only flag in non-test files (default: False means skip test files)
#   confidence  — default confidence for matches
# ─────────────────────────────────────────────────

SAST_RULES: list[dict] = [
    # ══════════════════════════════════════════════════════════════════════
    # Remote Code Execution
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "RCE-001", "severity": "CRITICAL",
        "title": "eval() with non-literal argument",
        # Python: eval(...), JS: eval(...) — but NOT .exec( which is RegExp
        "pattern": r"(?<!\w)eval\s*\((?![\"\'])",
        "category": "rce",
        "recommendation": "Replace eval() with safe parsers (json.loads, ast.literal_eval, JSON.parse).",
        "cve": "",
        "exclude": r"^\s*(//|#|\*|/\*)",  # skip comments
    },
    {
        "id": "RCE-002", "severity": "CRITICAL",
        "title": "Python exec() with dynamic content",
        # Only match Python exec(), not JS RegExp.exec() or .exec(
        "pattern": r"(?<!\.)(?<!\w)exec\s*\((?![\"\'])",
        "category": "rce",
        "recommendation": "Remove exec() calls. Use importlib or safe alternatives.",
        "cve": "",
        "langs": PYTHON_EXTS,  # Python only — avoids RegExp.exec() in JS/TS
    },
    {
        "id": "RCE-002b", "severity": "CRITICAL",
        "title": "child_process exec/execSync with dynamic content",
        # JS/TS: child_process.exec, execSync, require('child_process')
        "pattern": r"(child_process|require\s*\(\s*['\"]child_process['\"]\s*\))\s*\.\s*(exec|execSync|execFile)\s*\(",
        "category": "rce",
        "recommendation": "Use execFile/execFileSync with argument arrays instead of shell strings.",
        "cve": "",
        "langs": JS_TS_EXTS,
    },
    {
        "id": "RCE-003", "severity": "CRITICAL",
        "title": "subprocess with shell=True",
        "pattern": r"subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
        "category": "rce",
        "recommendation": "Set shell=False and pass command as a list.",
        "cve": "",
        "langs": PYTHON_EXTS,
    },
    {
        "id": "RCE-004", "severity": "CRITICAL",
        "title": "os.system() call",
        "pattern": r"\bos\.system\s*\(",
        "category": "rce",
        "recommendation": "Replace os.system() with subprocess.run() using a list of arguments.",
        "cve": "",
        "langs": PYTHON_EXTS,
    },
    {
        "id": "RCE-005", "severity": "HIGH",
        "title": "os.popen() call",
        "pattern": r"\bos\.popen\s*\(",
        "category": "rce",
        "recommendation": "Replace os.popen() with subprocess.run() with captured output.",
        "cve": "",
        "langs": PYTHON_EXTS,
    },
    {
        "id": "RCE-006", "severity": "HIGH",
        "title": "pickle deserialization",
        "pattern": r"\bpickle\.(load|loads)\s*\(",
        "category": "rce",
        "recommendation": "Never deserialize untrusted data with pickle. Use JSON or protobuf instead.",
        "cve": "",
        "langs": PYTHON_EXTS,
    },
    {
        "id": "RCE-007", "severity": "HIGH",
        "title": "Command injection via string formatting into shell call",
        "pattern": r'(os\.system|subprocess\.run|subprocess\.call|os\.popen)\s*\([^)]*(%s|\.format\(|f["\'])',
        "category": "rce",
        "recommendation": "Never construct shell commands from user input. Use argument lists.",
        "cve": "",
        "langs": PYTHON_EXTS,
    },

    # ══════════════════════════════════════════════════════════════════════
    # Path Traversal
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "PT-001", "severity": "HIGH",
        "title": "Python open() with variable path (potential file read/write)",
        # Python open() with a variable, not a string literal
        "pattern": r"(?<!\w)open\s*\(\s*[a-zA-Z_][a-zA-Z0-9_.]*\s*[,)]",
        "category": "path_traversal",
        "recommendation": "Validate file paths with pathlib.Path.resolve() and check against allowed base directories.",
        "cve": "",
        "langs": PYTHON_EXTS,  # Python only — avoids npm 'open' package in JS/TS
        # Skip common safe patterns: open("literal"), open(__file__)
        "exclude": r'open\s*\(\s*(["\']|__file__|os\.devnull)',
    },
    {
        "id": "PT-001b", "severity": "HIGH",
        "title": "fs.readFileSync/writeFileSync with variable path",
        # JS/TS fs operations with non-literal first arg
        "pattern": r"fs\.(readFileSync|writeFileSync|readFile|writeFile|createReadStream|createWriteStream)\s*\(\s*[a-zA-Z_]",
        "category": "path_traversal",
        "recommendation": "Validate file paths: resolve with path.resolve(), verify against an allowed base directory.",
        "cve": "",
        "langs": JS_TS_EXTS,
        # Skip env-var/config-derived paths and oauth token storage
        "exclude": r"(__|__dirname|__filename|packageJsonPath|configPath|caCertPath|tokenStoragePath|certPath|this\.|CERT|\.pem|\.crt|StoragePath)",
    },
    {
        "id": "PT-002", "severity": "HIGH",
        "title": "Path traversal sequence in runtime string (non-import, non-test)",
        # Match ../ in strings, but exclude import/require lines and comments
        "pattern": r"""["\']\.\.(/|\\)""",
        "category": "path_traversal",
        "recommendation": "Reject inputs containing '../' sequences. Normalize paths before use.",
        "cve": "",
        # Exclude: import/require statements, comments, test assertions
        "exclude": r"(^\s*(import|from|require|//|#|\*)|\.resolve\s*\(\s*__dirname)",
    },
    {
        "id": "PT-003", "severity": "MEDIUM",
        "title": "os.path.join with user input variable",
        "pattern": r"os\.path\.join\s*\([^)]*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
        "category": "path_traversal",
        "recommendation": "After os.path.join, call os.path.realpath() and verify result starts with the expected base.",
        "cve": "",
        "langs": PYTHON_EXTS,
    },
    {
        "id": "PT-004", "severity": "HIGH",
        "title": "Filesystem MCP CVE-2025-67366 pattern",
        "pattern": r"(read_file|write_file|list_directory)\s*\([^)]*\.\./[^)]*\)",
        "category": "path_traversal",
        "recommendation": "Patch filesystem-mcp to version >= 1.0.1 (CVE-2025-67366 fix).",
        "cve": "CVE-2025-67366",
    },

    # ══════════════════════════════════════════════════════════════════════
    # SSRF (Server-Side Request Forgery) — NEW
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "SSRF-001", "severity": "CRITICAL",
        "title": "User-controlled URL used in fetch/request without allowlist",
        # Matches: fetch(variable), axios.get(variable), http.request(variable)
        # where variable is NOT a string literal
        "pattern": r"(?:fetch|axios\.(?:get|post|put|delete|request)|http\.request|got|urllib\.request\.urlopen)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_.]*(?:\s*,|\s*\))",
        "category": "ssrf",
        "recommendation": "Validate URLs against an allowlist of approved hosts. Block private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x).",
        "cve": "",
        "confidence": "MEDIUM",
        # Skip when the variable name suggests an internally-constructed URL
        "exclude": r"(fetch|request)\s*\(\s*(GITLAB_API|BASE_URL|API_URL|config\.|process\.env|tokenUrl|authUrl|endpoint|options|url\.toString)",
    },
    {
        "id": "SSRF-002", "severity": "CRITICAL",
        "title": "API URL from HTTP request header without domain allowlist",
        # Pattern: reading URL from request headers and using it for outbound requests
        "pattern": r"""req\.(headers?|query|params|body)\s*\[?\s*['"](x-[a-z-]*url|api[_-]?url|redirect[_-]?uri|callback[_-]?url|target[_-]?url|endpoint)""",
        "category": "ssrf",
        "recommendation": "Never use URLs from request headers/params for server-side requests without validating against an allowlist of approved domains.",
        "cve": "",
    },
    {
        "id": "SSRF-003", "severity": "HIGH",
        "title": "URL constructed from user input with only format validation (new URL())",
        # new URL(userInput) is format validation only, not security validation
        "pattern": r"new\s+URL\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)\s*;?\s*(?!.*(?:allowlist|whitelist|allowed|hostname\s*[!=]==))",
        "category": "ssrf",
        "recommendation": "new URL() only validates format, not destination. Add hostname/domain allowlist checks after parsing.",
        "cve": "",
        "langs": JS_TS_EXTS,
        "confidence": "MEDIUM",
        # Exclude internal URL parsing (not user input)
        "exclude": r"new\s+URL\s*\(\s*(endpoint|baseUrl|apiUrl|url|tokenUrl|authUrl|redirectUrl|getEffective|config|GITLAB)",
    },

    # ══════════════════════════════════════════════════════════════════════
    # URL / API Path Injection — NEW
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "URLINJ-001", "severity": "HIGH",
        "title": "Unencoded string variable in URL path segment (potential path injection)",
        # Only flag variables whose names suggest user-controlled strings that could contain
        # path-traversal characters (paths, filenames, names, assets).
        # Numeric IDs (issueIid, mergeRequestIid, jobId, page, etc.) are safe to interpolate.
        # Server-constructed vars (getEffectiveApiUrl, membersPath, etc.) are safe.
        "pattern": r"`[^`]*/\$\{(?!encodeURIComponent\()(?:args\.)?((?:file|asset|direct_asset|local|save|dir|directory)[_pP]?[aA]?[tT]?[hH]?|filename|fname|file_name|secret|tag|ref_name|branch_name)\}",
        "category": "injection",
        "recommendation": "Always use encodeURIComponent() for user-controlled string values in URL path segments.",
        "cve": "",
        "langs": JS_TS_EXTS,
        "confidence": "HIGH",
        "exclude": r"(logger\.|console\.|\.info\(|\.warn\(|\.error\()",
    },
    {
        "id": "URLINJ-002", "severity": "HIGH",
        "title": "fetch() URL with unencoded user-controlled path variable",
        # Target fetch calls where a string-type user param (path, filename, name, etc.)
        # is interpolated in the URL template without encodeURIComponent.
        # Excludes numeric IDs and server-constructed base URLs.
        "pattern": r"(?:fetch|axios|got)\s*\(\s*`[^`]*/\$\{(?!encodeURIComponent)(?:args\.)?((?:file|asset|direct_asset|local|save|dir)[_pP]?[aA]?[tT]?[hH]?|filename|fname|file_name|secret)\}",
        "category": "injection",
        "recommendation": "Wrap user-supplied path segments with encodeURIComponent().",
        "cve": "",
        "langs": JS_TS_EXTS,
    },

    # ══════════════════════════════════════════════════════════════════════
    # Arbitrary File Read/Write via MCP Tools — NEW
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "AFR-001", "severity": "HIGH",
        "title": "Local filesystem read using MCP tool parameter without path sandboxing",
        # fs.readFileSync/existsSync/readFile with a function parameter directly
        "pattern": r"fs\.(readFileSync|existsSync|readFile|statSync)\s*\(\s*(filePath|file_path|localPath|local_path|inputPath)\b",
        "category": "path_traversal",
        "recommendation": "Resolve the path with path.resolve(), then verify it starts with an allowed base directory. Check for symlinks with fs.realpathSync().",
        "cve": "",
        "langs": JS_TS_EXTS,
    },
    {
        "id": "AFR-002", "severity": "HIGH",
        "title": "File write using path from MCP tool parameter without sandboxing",
        "pattern": r"fs\.(writeFileSync|writeFile|mkdirSync|mkdir)\s*\(\s*(filePath|file_path|savePath|save_path|localPath|outputPath)\b",
        "category": "path_traversal",
        "recommendation": "Validate the resolved path is within an allowed directory before writing.",
        "cve": "",
        "langs": JS_TS_EXTS,
        # Exclude oauth token storage (config-derived path, not user input)
        "exclude": r"(tokenStoragePath|configPath|this\.token)",
    },
    {
        "id": "AFR-003", "severity": "MEDIUM",
        "title": "Filename from external source used in path.join without sanitization",
        # path.join(dir, filename) where filename could contain ../
        "pattern": r"path\.join\s*\([^)]*,\s*(filename|file_?name|fname)\s*\)",
        "category": "path_traversal",
        "recommendation": "Strip directory components from filenames: use path.basename(filename) before path.join().",
        "cve": "",
        "langs": JS_TS_EXTS,
    },

    {
        "id": "SEC-007", "severity": "MEDIUM",
        "title": "Generic Bearer token in source",
        "pattern": r"[Bb]earer\s+[a-zA-Z0-9\-_\.]{20,}",
        "category": "secrets",
        "recommendation": "Remove hardcoded Bearer tokens. Obtain dynamically via OAuth.",
        "cve": "",
        # Skip regex patterns that match bearer tokens, and auth header construction
        "exclude": r"(regex|pattern|match|test\(|exec\(|\.exec|RegExp|headers\[)",
    },

    # ══════════════════════════════════════════════════════════════════════
    # Injection
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "INJ-001", "severity": "HIGH",
        "title": "SQL query construction via string concatenation",
        "pattern": r"(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*[a-zA-Z_]",
        "category": "injection",
        "recommendation": "Use parameterized queries or an ORM. Never concatenate user input into SQL.",
        "cve": "",
    },
    {
        "id": "INJ-002", "severity": "HIGH",
        "title": "LDAP injection vector",
        "pattern": r"ldap.*search.*\+\s*[a-zA-Z_]",
        "category": "injection",
        "recommendation": "Use LDAP libraries that support parameterized filters.",
        "cve": "",
    },
    {
        "id": "INJ-003", "severity": "MEDIUM",
        "title": "XML/XPath construction with user data",
        "pattern": r"(ElementTree|lxml|xpath)\.[^(]*\([^)]*\+",
        "category": "injection",
        "recommendation": "Validate and escape XML input. Use defusedxml library.",
        "cve": "",
    },
    {
        "id": "INJ-004", "severity": "MEDIUM",
        "title": "GraphQL query pass-through without depth/complexity limits",
        # Detects arbitrary GraphQL query forwarding
        "pattern": r"""JSON\.stringify\s*\(\s*\{\s*query\s*:\s*(args|params|req|input|body)\.""",
        "category": "injection",
        "recommendation": "Implement query depth limits, complexity analysis, or a query allowlist for GraphQL pass-through.",
        "cve": "",
        "langs": JS_TS_EXTS,
    },

    # ══════════════════════════════════════════════════════════════════════
    # MCP Server — Tool Handler Sinks
    # Rules that detect when MCP tool handler parameters flow into
    # dangerous sinks (shell, filesystem, network) without validation.
    # ══════════════════════════════════════════════════════════════════════

    # ── Python MCP servers (@tool decorator pattern) ──────────────────────
    {
        "id": "MCP-SINK-001", "severity": "CRITICAL",
        "title": "MCP @tool parameter flows to shell sink",
        "pattern": r'@(mcp\.tool|tool)\s*\n.*\ndef [^\n]+\([^\n]*\)[\s\S]{0,500}(os\.system|subprocess\.run.*shell=True|eval|exec)\s*\(',
        "category": "mcp_tool_sink",
        "recommendation": "Never pass @tool parameters to shell commands. Use subprocess with argument lists.",
        "cve": "",
        "langs": PYTHON_EXTS,
    },
    {
        "id": "MCP-SINK-002", "severity": "HIGH",
        "title": "MCP @tool parameter flows to open()/file read",
        "pattern": r'@(mcp\.tool|tool)\s*\n.*\ndef [^\n]+\([^\n]*\)[\s\S]{0,300}(?<!\w)open\s*\(\s*[a-zA-Z_]',
        "category": "mcp_tool_sink",
        "recommendation": "Validate file paths in @tool handlers: resolve, check against base directory, reject traversal.",
        "cve": "",
        "langs": PYTHON_EXTS,
    },
    {
        "id": "MCP-SINK-003", "severity": "HIGH",
        "title": "MCP @tool parameter flows to HTTP request (SSRF)",
        "pattern": r'@(mcp\.tool|tool)\s*\n.*\ndef [^\n]+\([^\n]*\)[\s\S]{0,500}(requests\.(get|post|put|delete)|urllib\.request\.urlopen|httpx\.(get|post))\s*\(\s*[a-zA-Z_]',
        "category": "mcp_tool_sink",
        "recommendation": "Validate URLs in @tool handlers against an allowlist. Block private IP ranges.",
        "cve": "",
        "langs": PYTHON_EXTS,
    },

    # ── JS/TS MCP servers (server.setRequestHandler / case "tool_name" pattern) ──
    {
        "id": "MCP-SINK-004", "severity": "CRITICAL",
        "title": "MCP tool handler passes args to child_process",
        # JS/TS: inside a case handler, args flow to exec/spawn
        "pattern": r'(child_process\.(exec|execSync|spawn)|require\s*\(\s*[\'"]child_process[\'"]\s*\))\s*\([^)]*args\.',
        "category": "mcp_tool_sink",
        "recommendation": "Never pass MCP tool arguments to shell commands. Use execFile with argument arrays.",
        "cve": "",
        "langs": JS_TS_EXTS,
    },
    {
        "id": "MCP-SINK-005", "severity": "HIGH",
        "title": "MCP tool handler reads local file using args parameter",
        # fs.readFileSync(args.file_path) or similar in tool handler context
        "pattern": r'fs\.(readFileSync|readFile|createReadStream|existsSync)\s*\(\s*args\.',
        "category": "mcp_tool_sink",
        "recommendation": "Validate and sandbox file paths from MCP tool args: path.resolve() + base directory check + path.basename() for filenames.",
        "cve": "",
        "langs": JS_TS_EXTS,
    },
    {
        "id": "MCP-SINK-006", "severity": "HIGH",
        "title": "MCP tool handler writes local file using args parameter",
        "pattern": r'fs\.(writeFileSync|writeFile|mkdirSync)\s*\(\s*args\.',
        "category": "mcp_tool_sink",
        "recommendation": "Validate destination paths from MCP tool args before writing. Check against allowed directories.",
        "cve": "",
        "langs": JS_TS_EXTS,
    },
    {
        "id": "MCP-SINK-007", "severity": "HIGH",
        "title": "MCP tool handler uses args in fetch/HTTP request URL (SSRF)",
        # fetch(`...${args.url}...`) or fetch(args.url)
        "pattern": r'(?:fetch|axios|got|http\.request)\s*\([^)]*args\.',
        "category": "mcp_tool_sink",
        "recommendation": "Never use MCP tool args as URLs without allowlist validation. Block internal IPs.",
        "cve": "",
        "langs": JS_TS_EXTS,
    },

    # ══════════════════════════════════════════════════════════════════════
    # MCP Server — Transport & Session Security
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "MCP-TRANSPORT-001", "severity": "INFO",
        "title": "SSE transport endpoint — verify auth is handled at MCP protocol layer",
        # In MCP servers, SSE is the standard transport. Auth is typically at the protocol
        # level (per-request tokens), not HTTP middleware. Flag for review, not as a vuln.
        "pattern": r"""app\.get\s*\(\s*['"]/(sse|events|stream)['"]""",
        "category": "mcp_transport",
        "recommendation": "Verify auth is enforced at MCP protocol layer (per-request tokens). If multi-tenant, add session isolation.",
        "cve": "",
        "langs": JS_TS_EXTS,
        "confidence": "LOW",
    },
    {
        "id": "MCP-TRANSPORT-002", "severity": "MEDIUM",
        "title": "SSE response without Origin validation",
        "pattern": r"""res\.(setHeader|writeHead|set)\s*\([^)]*['"]text/event-stream['"]""",
        "category": "mcp_transport",
        "recommendation": "Validate Origin header on SSE connections. Implement CORS restrictions.",
        "cve": "",
        "langs": JS_TS_EXTS,
    },
    {
        "id": "MCP-TRANSPORT-003", "severity": "CRITICAL",
        "title": "Empty or shared session identifier (neighbor jacking)",
        "pattern": r"""(session_id|client_id|sessionId)\s*=\s*['"]["']""",
        "category": "mcp_transport",
        "recommendation": "Use crypto.randomUUID() or equivalent for session IDs. Never use empty/shared identifiers.",
        "cve": "",
    },
    {
        "id": "MCP-TRANSPORT-004", "severity": "MEDIUM",
        "title": "MCP server binding to 0.0.0.0 (public network exposure)",
        "pattern": r"""(host\s*=\s*['"]0\.0\.0\.0['"]|listen\s*\([^)]*['"]0\.0\.0\.0['"]|\.listen\s*\(\s*\d+\s*\))""",
        "category": "mcp_transport",
        "recommendation": "Bind to 127.0.0.1 for local-only access. Public MCP servers need authentication.",
        "cve": "",
    },
    {
        "id": "MCP-TRANSPORT-005", "severity": "HIGH",
        "title": "Auth token forwarded to user-controlled URL (credential leak via SSRF)",
        # buildAuthHeaders or auth token included in fetch to dynamic URL
        "pattern": r"(buildAuthHeaders|[Aa]uth.*[Hh]eader|[Pp]rivate.?[Tt]oken|[Bb]earer)[\s\S]{0,200}fetch\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]",
        "category": "mcp_transport",
        "recommendation": "Never send auth credentials to user-controlled URLs. Validate destination against allowlist before attaching tokens.",
        "cve": "",
        "confidence": "MEDIUM",
    },

    # ══════════════════════════════════════════════════════════════════════
    # MCP Server — Schema & Input Validation
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "MCP-SCHEMA-001", "severity": "MEDIUM",
        "title": "Zod schema accepts unbounded string on content/body field (DoS risk)",
        "pattern": r"""(content|body|query|message|payload|description)\s*:\s*z\.string\s*\(\s*\)\.describe\(""",
        "category": "mcp_schema",
        "recommendation": "Add .max() length constraint to prevent memory exhaustion via oversized payloads.",
        "cve": "",
        "langs": JS_TS_EXTS,
        "confidence": "MEDIUM",
    },
    {
        "id": "MCP-SCHEMA-002", "severity": "MEDIUM",
        "title": "File path parameter without validation constraints",
        # z.string().describe("...path...") without .regex() or custom refinement
        "pattern": r"""(file_?path|local_?path|dir(?:ectory)?_?path|save_?path)\s*:\s*z\.string\s*\(\s*\)\.describe\(""",
        "category": "mcp_schema",
        "recommendation": "Add .regex() or .refine() to reject path traversal sequences and absolute paths in schema.",
        "cve": "",
        "langs": JS_TS_EXTS,
    },
    {
        "id": "MCP-SCHEMA-003", "severity": "MEDIUM",
        "title": "URL parameter without format validation in schema",
        "pattern": r"""(url|endpoint|webhook|callback|redirect)\s*:\s*z\.string\s*\(\s*\)\.describe\(""",
        "category": "mcp_schema",
        "recommendation": "Add .url() validator or .refine() with allowlist check for URL parameters.",
        "cve": "",
        "langs": JS_TS_EXTS,
        "confidence": "MEDIUM",
    },
    {
        "id": "MCP-SCHEMA-004", "severity": "LOW",
        "title": "MCP tool accepts z.any() or z.record(z.any()) (no type safety)",
        "pattern": r""":\s*z\.(any|record\s*\(\s*z\.any)\s*\(\s*\)""",
        "category": "mcp_schema",
        "recommendation": "Define specific types instead of z.any(). Loose schemas allow unexpected data to reach sinks.",
        "cve": "",
        "langs": JS_TS_EXTS,
        "confidence": "LOW",
    },

    # ══════════════════════════════════════════════════════════════════════
    # MCP Server — Tool Poisoning & Description Mismatch
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "MCP-POISON-001", "severity": "HIGH",
        "title": "Tool description contains hidden instructions or prompt injection (JS/TS)",
        # JS/TS: .describe() with embedded injection tags
        "pattern": r"""\.describe\s*\(\s*['"][^'"]*(<\/?[a-z]|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|IMPORTANT|IGNORE|SYSTEM|OVERRIDE|YOU MUST|DO NOT TELL)""",
        "category": "mcp_poisoning",
        "recommendation": "Tool descriptions should be plain text. Remove HTML tags, encoded chars, and prompt injection patterns.",
        "cve": "",
        "langs": JS_TS_EXTS,
        "confidence": "MEDIUM",
    },
    {
        "id": "MCP-POISON-001b", "severity": "CRITICAL",
        "title": "Prompt injection tags in Python @tool docstring",
        # Python: docstrings with <IMPORTANT>, <HIDDEN>, <SYSTEM>, or LLM instruction patterns
        # These are the primary tool poisoning vector in Python MCP servers
        "pattern": r'<(IMPORTANT|HIDDEN|SYSTEM|SECRET|OVERRIDE|INTERNAL|ADMIN|CONFIDENTIAL)>',
        "category": "mcp_poisoning",
        "recommendation": "Remove XML/HTML-like instruction tags from tool docstrings. These are prompt injection vectors that manipulate LLM behavior.",
        "cve": "",
        "confidence": "HIGH",
    },
    {
        "id": "MCP-POISON-002", "severity": "HIGH",
        "title": "LLM instruction keywords in tool docstring (prompt injection)",
        # Common instruction patterns used to manipulate LLM behavior via tool descriptions
        "pattern": r'("""|\'\'\')\s*[^"]*?(you must first access|do not mention|do not tell|include .{0,30} in your response|present .{0,30} as if|do not explicitly mention)',
        "category": "mcp_poisoning",
        "recommendation": "Tool descriptions should describe functionality, not contain behavioral instructions for the LLM.",
        "cve": "",
        "langs": PYTHON_EXTS,
        "confidence": "HIGH",
    },
    {
        "id": "MCP-POISON-003", "severity": "MEDIUM",
        "title": "Homoglyph or unicode in tool name (typosquatting)",
        # Non-ASCII in tool registration names
        "pattern": r"""(name|toolName)\s*[:=]\s*['"][^'"]*[^\x00-\x7f][^'"]*['"]""",
        "category": "mcp_poisoning",
        "recommendation": "Tool names must be ASCII-only. Unicode characters enable typosquatting attacks.",
        "cve": "",
    },
    {
        "id": "MCP-POISON-004", "severity": "HIGH",
        "title": "Token/secret exposed in MCP tool return value or error message",
        # Catches: return f"...{token}..." or f"Your token is: {token}"
        # but NOT: return {"Private-Token": token}  (object/dict construction is OK internally)
        "pattern": r"""return\s+f['"][^'"]*\{[^}]*(token|api_key|password|secret|bearer|jwt|access_key|refresh_token)[^}]*\}[^'"]*['"]""",
        "category": "mcp_poisoning",
        "recommendation": "Never expose tokens, API keys, or credentials in tool responses or error messages.",
        "cve": "",
        "confidence": "MEDIUM",
        "exclude": r"(#\s|//\s|verify|validate|invalid|format|check|test)",
    },
    {
        "id": "MCP-POISON-005", "severity": "HIGH",
        "title": "Tool behavior changes based on call count (rug pull pattern)",
        # Detects mutable state that modifies tool behavior over time
        "pattern": r"(call_count|request_count|num_calls|invocation_count)\s*(\+\=\s*1|=\s*.*\+\s*1)[\s\S]{0,500}(if\s+.*call_count|if\s+.*request_count|if\s+.*num_calls)",
        "category": "mcp_poisoning",
        "recommendation": "Tool behavior should be deterministic. Mutable call counters that alter behavior are a rug pull pattern.",
        "cve": "",
        "confidence": "MEDIUM",
    },

    # ══════════════════════════════════════════════════════════════════════
    # MCP Server — Configuration & Deployment
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "MCP-CONFIG-001", "severity": "HIGH",
        "title": "Debug mode enabled in production server",
        "pattern": r"(debug\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|NODE_ENV.*development)",
        "category": "mcp_config",
        "recommendation": "Disable debug mode in production. Use environment-based configuration.",
        "cve": "",
    },
    {
        "id": "MCP-CONFIG-002", "severity": "LOW",
        "title": "Unpinned dependency (supply chain risk)",
        "pattern": r"^[a-zA-Z][a-zA-Z0-9\-_]*\s*$",
        "category": "mcp_config",
        "recommendation": "Pin all dependencies with exact versions to prevent supply chain attacks.",
        "cve": "",
    },
    {
        "id": "MCP-CONFIG-003", "severity": "MEDIUM",
        "title": "CORS wildcard allows any origin",
        "pattern": r"""cors\s*\(\s*\{[^}]*origin\s*:\s*['"\*]|Access-Control-Allow-Origin['"]\s*,\s*['"\*]""",
        "category": "mcp_config",
        "recommendation": "Restrict CORS origin to known clients. Wildcard enables cross-site tool invocation.",
        "cve": "",
    },
    {
        "id": "MCP-CONFIG-004", "severity": "INFO",
        "title": "MCP server instantiation — verify rate limiting is configured",
        # Flag only SSE/HTTP transports (STDIO is single-user, no rate limit needed)
        "pattern": r"""new\s+(SSEServerTransport|StreamableHTTPServerTransport)\s*\(""",
        "category": "mcp_config",
        "recommendation": "Implement per-session and per-tool rate limiting for network-exposed MCP transports.",
        "cve": "",
        "confidence": "LOW",
    },

    # ══════════════════════════════════════════════════════════════════════
    # Secret / Credential Exposure
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "SEC-001", "severity": "CRITICAL",
        "title": "AWS Access Key hardcoded",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "category": "secrets",
        "recommendation": "Remove hardcoded AWS keys. Use environment variables or IAM roles.",
        "cve": "",
    },
    {
        "id": "SEC-002", "severity": "CRITICAL",
        "title": "OpenAI / Anthropic API key hardcoded",
        "pattern": r"(?<!['\"\w/])(sk-[a-zA-Z0-9\-]{20,}|sk-ant-[a-zA-Z0-9\-]{20,})",
        "category": "secrets",
        "recommendation": "Remove hardcoded API keys. Load from environment variables.",
        "cve": "",
        "exclude": r"(process\.env|os\.environ|getenv|\.example|\.sample|EXAMPLE|PLACEHOLDER|your[_-])",
    },
    {
        "id": "SEC-003", "severity": "CRITICAL",
        "title": "Private key material in source",
        "pattern": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "category": "secrets",
        "recommendation": "Remove private keys from source. Store in secure vaults.",
        "cve": "",
    },
    {
        "id": "SEC-004", "severity": "HIGH",
        "title": "Hardcoded password/secret assignment",
        "pattern": r"""(password|passwd|secret|api_key|apikey|token)\s*=\s*['"][^'"]{8,}['"]""",
        "category": "secrets",
        "recommendation": "Move secrets to environment variables or a secrets manager.",
        "cve": "",
        "exclude": r"(process\.env|os\.environ|getenv|\.example|test|mock|fake|dummy|placeholder|describe\(|\.parse)",
    },
    {
        "id": "SEC-005", "severity": "HIGH",
        "title": "Database connection string with credentials",
        "pattern": r"(mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@",
        "category": "secrets",
        "recommendation": "Remove credentials from connection strings. Use environment variables.",
        "cve": "",
    },
    {
        "id": "SEC-006", "severity": "HIGH",
        "title": "GitLab/GitHub token pattern hardcoded",
        "pattern": r"(glpat-[a-zA-Z0-9\-_]{20,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})",
        "category": "secrets",
        "recommendation": "Rotate the token immediately and remove from source.",
        "cve": "",
        "exclude": r"(process\.env|os\.environ|getenv|validate|regex|pattern|test|mock)",
    },

    # ══════════════════════════════════════════════════════════════════════
    # CVE-Specific Patterns
    # ══════════════════════════════════════════════════════════════════════
    {
        "id": "CVE-FS-001", "severity": "HIGH",
        "title": "Filesystem MCP CVE-2025-67366 (path traversal in tool handler)",
        "pattern": r"(read_file|write_file|list_directory)\s*\([^)]*\.\./[^)]*\)",
        "category": "cve",
        "recommendation": "Patch filesystem-mcp to version >= 1.0.1.",
        "cve": "CVE-2025-67366",
    },
    {
        "id": "CVE-GEMINI-001", "severity": "HIGH",
        "title": "Gemini MCP command injection (CVE-2026-0755)",
        "pattern": r"(gemini|google\.generativeai)[^#\n]*(subprocess|os\.system|eval|exec)",
        "category": "cve",
        "recommendation": "Patch gemini-mcp-tool to version fixing CVE-2026-0755.",
        "cve": "CVE-2026-0755",
    },
    {
        "id": "CVE-MCPJAM-001", "severity": "CRITICAL",
        "title": "MCPJam Inspector RCE (CVE-2026-23744)",
        "pattern": r"(inspector|mcpjam)[^#\n]*(exec|eval|child_process|spawn)\s*\(",
        "category": "cve",
        "recommendation": "Patch MCPJam Inspector to version fixing CVE-2026-23744.",
        "cve": "CVE-2026-23744",
    },
    {
        "id": "CVE-WA-001", "severity": "CRITICAL",
        "title": "WhatsApp MCP message exfiltration pattern",
        "pattern": r"(whatsapp|wa_token|WABA)[^=]*=\s*[\"'][A-Za-z0-9+/]{20,}",
        "category": "cve",
        "recommendation": "Remove WhatsApp API credentials from source. Use environment variables.",
        "cve": "",
    },
]


def _is_test_file(filepath: Path) -> bool:
    """Check if a file is a test file based on path/name patterns."""
    return bool(TEST_PATTERNS.search(str(filepath)))


def _get_file_lang(filepath: Path) -> Optional[str]:
    """Return 'python' or 'js_ts' based on extension, or None."""
    ext = filepath.suffix.lower()
    if ext in PYTHON_EXTS:
        return "python"
    if ext in JS_TS_EXTS:
        return "js_ts"
    return None


class SASTScanner:
    """
    Regex-based static analysis scanner for MCP server source code.

    Scans Python and JavaScript/TypeScript files for vulnerabilities.
    Supports language-aware rules and false-positive exclusion filters.
    """

    SUPPORTED_EXTENSIONS = ALL_EXTS
    SKIP_DIRS = {"node_modules", "__pycache__", ".git", "venv", ".venv", "dist", "build"}

    def __init__(self, rules: list[dict] = None, include_tests: bool = False):
        self.rules = rules or SAST_RULES
        self.findings: list[SASTFinding] = []
        self.include_tests = include_tests

    def _rule_applies_to_file(self, rule: dict, filepath: Path, file_lang: Optional[str]) -> bool:
        """Check if a rule should apply to this file based on language targeting."""
        rule_langs = rule.get("langs")
        if rule_langs is None:
            return True  # rule applies to all languages
        ext = filepath.suffix.lower()
        return ext in rule_langs

    def _is_excluded(self, rule: dict, line_text: str) -> bool:
        """Check if the matched line should be excluded by the rule's exclude pattern."""
        exclude_pattern = rule.get("exclude")
        if not exclude_pattern:
            return False
        try:
            return bool(re.search(exclude_pattern, line_text, re.IGNORECASE))
        except re.error:
            return False

    def scan_file(self, filepath: Path) -> list[SASTFinding]:
        """Scan a single file for vulnerabilities."""
        findings = []
        is_test = _is_test_file(filepath)
        file_lang = _get_file_lang(filepath)

        # Skip test files unless explicitly included
        if is_test and not self.include_tests:
            return findings

        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()

            for rule in self.rules:
                rule_id = rule["id"]
                pattern = rule["pattern"]

                # Language filtering
                if not self._rule_applies_to_file(rule, filepath, file_lang):
                    continue

                # requirements.txt / package.json — line-by-line
                if rule_id == "MCP-004" and filepath.name in ("requirements.txt", "package.json"):
                    for lineno, line in enumerate(lines, 1):
                        stripped = line.strip()
                        if re.match(pattern, stripped) and stripped:
                            findings.append(SASTFinding(
                                rule_id=rule_id,
                                severity=rule["severity"],
                                title=rule["title"],
                                description=f"Unpinned dependency: '{stripped}'",
                                file=str(filepath),
                                line=lineno,
                                code_snippet=stripped,
                                recommendation=rule["recommendation"],
                                category=rule["category"],
                                cve=rule.get("cve", ""),
                            ))
                    continue

                # General regex scan
                try:
                    for match in re.finditer(pattern, content, re.MULTILINE):
                        lineno = content[:match.start()].count("\n") + 1
                        col = match.start() - content.rfind("\n", 0, match.start()) - 1
                        snippet = lines[lineno - 1].strip() if lineno <= len(lines) else ""

                        # Apply exclude filter on the matched line
                        if self._is_excluded(rule, snippet):
                            continue

                        findings.append(SASTFinding(
                            rule_id=rule_id,
                            severity=rule["severity"],
                            title=rule["title"],
                            description=f"Pattern matched in {filepath.name}",
                            file=str(filepath),
                            line=lineno,
                            column=col,
                            code_snippet=snippet[:120],
                            recommendation=rule["recommendation"],
                            category=rule["category"],
                            cve=rule.get("cve", ""),
                            confidence=rule.get("confidence", "HIGH"),
                        ))
                except re.error:
                    pass

        except Exception as e:
            console.print(f"[yellow]SAST: Could not read {filepath}: {e}[/yellow]")

        return findings

    def scan_directory(self, path: Path) -> list[SASTFinding]:
        """Recursively scan a directory."""
        all_findings = []
        target = Path(path)

        files_to_scan = []
        for ext in self.SUPPORTED_EXTENSIONS:
            files_to_scan.extend(target.rglob(f"*{ext}"))

        # Also scan requirements.txt and package.json
        files_to_scan.extend(target.rglob("requirements.txt"))
        files_to_scan.extend(target.rglob("package.json"))

        for f in files_to_scan:
            if any(skip in f.parts for skip in self.SKIP_DIRS):
                continue
            findings = self.scan_file(f)
            all_findings.extend(findings)

        self.findings = all_findings
        return all_findings

    def scan_string(self, code: str, filename: str = "<string>") -> list[SASTFinding]:
        """Scan a code string directly."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tf:
            tf.write(code)
            tmp_path = Path(tf.name)
        findings = self.scan_file(tmp_path)
        tmp_path.unlink()
        for f in findings:
            f.file = filename
        return findings

    def print_results(self, findings: list[SASTFinding] = None):
        """Print findings as a Rich table."""
        from rich.panel import Panel
        flist = findings or self.findings

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        flist.sort(key=lambda f: severity_order.get(f.severity, 5))

        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }

        table = Table(title="SAST Findings", show_lines=True, expand=True)
        table.add_column("ID", style="bold", width=10)
        table.add_column("Severity", width=10)
        table.add_column("Title", max_width=40)
        table.add_column("File:Line", max_width=30)
        table.add_column("Snippet", max_width=50)
        table.add_column("CVE", width=16)

        for f in flist:
            color = severity_colors.get(f.severity, "white")
            table.add_row(
                f.rule_id,
                f"[{color}]{f.severity}[/{color}]",
                f.title,
                f"{Path(f.file).name}:{f.line}",
                f.code_snippet,
                f.cve or "-",
            )

        console.print(table)
        console.print(f"\n[bold]Total findings: {len(flist)}[/bold]")

        # Summary by severity
        from collections import Counter
        counts = Counter(f.severity for f in flist)
        summary_parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts[sev]:
                color = severity_colors[sev]
                summary_parts.append(f"[{color}]{sev}: {counts[sev]}[/{color}]")
        console.print("  " + "  |  ".join(summary_parts))

    def to_dict(self) -> list[dict]:
        """Export findings as list of dicts."""
        return [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "file": f.file,
                "line": f.line,
                "code_snippet": f.code_snippet,
                "recommendation": f.recommendation,
                "category": f.category,
                "cve": f.cve,
                "confidence": f.confidence,
            }
            for f in self.findings
        ]
