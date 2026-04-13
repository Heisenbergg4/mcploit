# MCPloit

A security testing tool for MCP (Model Context Protocol) servers. Built to enumerate, scan, and actively exploit vulnerabilities in MCP implementations — both black-box (live servers) and white-box (source code).

---

## What it does

MCP servers are increasingly being used to give LLMs access to tools, files, and external services. That also makes them an attack surface. MCPloit lets you:

- **Enumerate** what tools, resources, and prompts a server exposes
- **Connect** to MCP servers for manual testing, custom payload execution, and studying tool behavior
- **Scan** for common vulnerabilities passively (no active probing)
- **Audit** source code with SAST rules + optional Claude AI review
- **Exploit** specific vulnerabilities with a library of 99 payloads
- **Test** CVE-specific attack paths against known vulnerable servers

---

## Install

```bash
git clone https://github.com/Heisenbergg4/mcploit.git
cd mcploit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional — needed only for `--ai` flag:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

### Connect to a server (interactive shell)
```bash
python3 mcploit.py connect http://localhost:9001/sse
python3 mcploit.py connect ./server.py          # STDIO
```

### Enumerate capabilities
```bash
python3 mcploit.py enum http://localhost:9001/sse
python3 mcploit.py enum ./server.py -o results.json
```

### Passive vulnerability scan
```bash
python3 mcploit.py scan http://localhost:9001/sse
python3 mcploit.py scan ./server.py -d prompt_injection,code_execution
```

### Scan with active probing (confirms vulnerabilities)
```bash
python3 mcploit.py scan http://localhost:9001/sse --probe --schema
```

### Audit source code
```bash
# SAST only (fast, no API key needed)
python3 mcploit.py audit ./server-src/ --sast-only

# Full pipeline with AI triage
python3 mcploit.py audit ./server-src/ --ai --markdown report.md
```

### Run exploits
```bash
# Auto-run all payloads for a module
python3 mcploit.py exploit http://localhost:9001/sse -m prompt_injection --auto

# Pick payloads interactively
python3 mcploit.py exploit http://localhost:9001/sse -m path_traversal --interactive

# Target a specific tool
python3 mcploit.py exploit http://localhost:9008/sse -m rce --tool evaluate_expression --auto
```

### CVE-specific exploits
```bash
python3 mcploit.py cve-exploit http://localhost:9001/sse --cve CVE-2025-67366
python3 mcploit.py cve-exploit http://localhost:9009/sse --cve CVE-2026-0755
```

### Full assessment
```bash
python3 mcploit.py full-scan http://localhost:9001/sse \
  --source ./server-src/ --ai --probe --accept-disclaimer \
  -o full.json --markdown report.md
```

---

## Module aliases

| Alias | Module |
|-------|--------|
| `pi`, `injection` | `prompt_injection` |
| `rce`, `exec`, `ce` | `code_execution` |
| `pt`, `traversal`, `lfi` | `path_traversal` |
| `poison` | `tool_poisoning` |
| `tm`, `rug`, `shadow` | `tool_manipulation` |
| `secrets`, `creds` | `secrets_exposure` |
| `token`, `theft` | `token_theft` |

---

## Payload library

99 payloads across 7 categories. List them with:

```bash
python3 mcploit.py payloads list
python3 mcploit.py payloads show rce
```

---

## White-box analysis pipeline

When you point `audit` at source code, it runs three layers:

1. **SAST** — 31 regex rules covering RCE, path traversal, secrets, injection, and MCP-specific issues. Runs in ~2 seconds.
2. **AST analysis** — extracts `@tool` functions, checks for `shell=True`, traces param-to-sink data flow
3. **AI review** (optional, `--ai`) — sends HIGH/CRITICAL findings and each `@tool` to Claude for triage. Flags true positives with `[AI]`.

---

## Supported transports

- **STDIO** — Python or Node.js scripts (`./server.py`, `./server.js`)
- **SSE** — `http://host/sse`
- **HTTP** — `http://host/mcp`
- Auto-detected from the target string if `--transport` is not set

---

## CVEs covered

| CVE | Server | Vulnerability |
|-----|--------|---------------|
| CVE-2025-67366 | filesystem-mcp | Path traversal |
| CVE-2026-0755 | gemini-mcp-tool | Command injection |
| CVE-2026-23744 | MCPJam Inspector | RCE |

---

## Burp Suite

Route traffic through Burp for interception and replay:

```bash
python3 mcploit.py scan http://localhost:9001/sse --probe --burp-host 127.0.0.1 --burp-port 8080
```

Requests are also logged to `burp_mcploit.log` in Burp-importable JSON format.

---

## Notes

- `--probe` and `--run-cve` require `--accept-disclaimer` (or `MCPLOIT_ACCEPTED_DISCLAIMER=1`)
- Default mode is safe — canary payloads only, no writes, no shells
- `--unsafe` enables the full destructive payload set
- `--ai` sends source code to the Anthropic API — don't use on proprietary code without clearance
- Never run the included vulnerable lab servers on a public network

---

## License

For authorized security testing only.
