"""Code Execution vulnerability detector.

Detects arbitrary code/command execution vulnerabilities:
- Direct code execution (eval, exec, subprocess)
- Shell command injection
- Script execution capabilities
- Unsafe parameter handling
"""

from .base_detector import (
    BaseDetector,
    DetectorContext,
    Vulnerability,
    Severity,
    Confidence,
)


class CodeExecutionDetector(BaseDetector):
    """Detects code and command execution vulnerabilities."""

    name = "Code Execution Detector"
    description = "Detects arbitrary code and command execution vulnerabilities"
    vulnerability_types = ["code_execution", "command_injection", "rce"]

    # Direct code execution patterns.
    # Note: "eval" and "exec" use \b word boundaries to avoid matching
    # "evaluate", "execute" (verb), "execution" (noun), etc. in descriptions.
    CODE_EXECUTION_PATTERNS = [
        ("execute_code", False),
        ("execute_python", False),
        ("execute_javascript", False),
        ("execute_script", False),
        ("run_code", False),
        ("run_script", False),
        ("run_python", False),
        (r"\beval\b", True),          # word-boundary: avoids "evaluate", "retrieval"
        (r"\bexec\b", True),          # word-boundary: avoids "execute" (verb), "execution"
        ("code_execution", False),
        ("script_execution", False),
        (r"\binterpreter\b", True),   # word-boundary: avoids "interpreted language" mentions
        ("repl", False),
    ]

    # Shell/command execution patterns.
    # Removed broad tokens: "bash"/"cmd" alone appear in docs/descriptions legitimately.
    # Keep compound forms that specifically indicate execution capability.
    SHELL_EXECUTION_PATTERNS = [
        ("execute_shell", False),
        ("execute_command", False),
        ("run_command", False),
        ("run_shell", False),
        ("shell_command", False),
        ("shell_exec", False),
        ("system_command", False),
        ("subprocess", False),
        ("command_line", False),
        (r"\bterminal\b", True),
        # "bash" and "cmd" only as standalone tool names, not in descriptions
        (r"^(bash|cmd|powershell)$", True),
    ]

    # Network command patterns (command injection vectors)
    NETWORK_COMMAND_PATTERNS = [
        ("ping", False),
        ("traceroute", False),
        ("nslookup", False),
        ("dig", False),
        ("netstat", False),
        ("curl", False),
        ("wget", False),
        ("ssh", False),
        ("telnet", False),
        ("nc", False),
        ("netcat", False),
        ("nmap", False),
    ]

    # Command injection indicators in parameters
    INJECTABLE_PARAM_PATTERNS = [
        ("host", False),
        ("hostname", False),
        ("ip", False),
        ("address", False),
        ("url", False),
        ("command", False),
        ("cmd", False),
        ("args", False),
        ("arguments", False),
        ("options", False),
        ("flags", False),
        ("params", False),
        ("format", False),  # Often used in eval() scenarios
        ("template", False),
        ("expression", False),
        ("script", False),
        ("code", False),
    ]

    # Dangerous function indicators
    DANGEROUS_INDICATORS = [
        (r"os\.", True),
        (r"subprocess", True),
        (r"eval\s*\(", True),
        (r"exec\s*\(", True),
        (r"system\s*\(", True),
        (r"popen", True),
        (r"spawn", True),
        (r"fork", True),
        (r"process\.env", True),
        (r"child_process", True),
        (r"shell\s*=\s*True", True),
    ]

    def detect(self, context: DetectorContext) -> list[Vulnerability]:
        """Detect code execution vulnerabilities."""
        self.vulnerabilities = []

        for tool in context.tools:
            self._check_tool_for_code_execution(tool)

        return self.vulnerabilities

    def _check_tool_for_code_execution(self, tool):
        """Check a tool for code execution vulnerabilities."""
        tool_text = self._get_tool_text(tool)

        # Check for direct code execution
        code_exec_matches = self._check_text_patterns(
            tool_text,
            self.CODE_EXECUTION_PATTERNS
        )

        if code_exec_matches:
            self._add_vulnerability(
                name="Arbitrary Code Execution",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool provides direct code execution capability: {', '.join(code_exec_matches)}",
                details={"patterns": code_exec_matches},
                exploit_hint="Execute arbitrary code through this tool - try system commands, file access, env vars"
            )

        # Check for shell command execution
        shell_exec_matches = self._check_text_patterns(
            tool_text,
            self.SHELL_EXECUTION_PATTERNS
        )

        if shell_exec_matches:
            self._add_vulnerability(
                name="Shell Command Execution",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool provides shell command execution: {', '.join(shell_exec_matches)}",
                details={"patterns": shell_exec_matches},
                exploit_hint="Execute shell commands - try command chaining with ;, &&, ||, or |"
            )

        # Check for network commands (potential command injection vectors)
        # Note: Many network tools use safe library functions, not shell commands
        # Only flag as HIGH if there are shell execution indicators
        network_cmd_matches = self._check_text_patterns(
            tool_text,
            self.NETWORK_COMMAND_PATTERNS
        )

        if network_cmd_matches:
            # Check for indicators that the tool actually uses shell commands
            shell_indicators = self._check_text_patterns(
                tool_text,
                [
                    (r"executes?\s*(shell|command|system)", True),
                    (r"subprocess", True),
                    (r"system\s*\(", True),
                    (r"shell\s*=\s*True", True),
                    (r"child_process", True),
                    (r"os\.system", True),
                    (r"popen", True),
                ]
            )

            # Check for injectable parameters
            injectable_params = self._find_injectable_params(tool)

            if injectable_params and shell_indicators:
                # HIGH confidence: has shell execution indicators AND injectable params
                self._add_vulnerability(
                    name="Command Injection via Network Tool",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    item_type="tool",
                    item_name=tool.name,
                    reason=f"Network command tool ({', '.join(network_cmd_matches)}) with shell indicators ({', '.join(shell_indicators)}) and injectable parameters: {', '.join(injectable_params)}",
                    details={
                        "network_commands": network_cmd_matches,
                        "injectable_params": injectable_params,
                        "shell_indicators": shell_indicators
                    },
                    exploit_hint="Inject commands via parameters using ; or && - e.g., '127.0.0.1; cat /etc/passwd'"
                )
            elif injectable_params:
                # LOW confidence: network tool with injectable params but no shell indicators
                # Could be using safe library functions
                self._add_vulnerability(
                    name="Network Tool with Injectable Parameters",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    item_type="tool",
                    item_name=tool.name,
                    reason=f"Network tool ({', '.join(network_cmd_matches)}) accepts user input via: {', '.join(injectable_params)}. May use safe library functions.",
                    details={
                        "network_commands": network_cmd_matches,
                        "injectable_params": injectable_params,
                        "note": "No shell execution indicators found - likely uses library functions"
                    },
                    exploit_hint="Verify if tool uses shell commands before attempting injection"
                )

        # Check for format/template parameters (eval injection)
        if tool.inputSchema and "properties" in tool.inputSchema:
            for param_name, param_info in tool.inputSchema["properties"].items():
                # Check for format/template parameters
                if any(p in param_name.lower() for p in ["format", "template", "expression", "code", "script"]):
                    self._add_vulnerability(
                        name="Potential Eval Injection",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        item_type="tool",
                        item_name=tool.name,
                        reason=f"Parameter '{param_name}' may be evaluated as code",
                        details={"parameter": param_name, "info": param_info},
                        exploit_hint=f"Try injecting code via the '{param_name}' parameter"
                    )

        # Check for dangerous function indicators in description
        if tool.description:
            dangerous_matches = self._check_text_patterns(
                tool.description,
                self.DANGEROUS_INDICATORS
            )
            if dangerous_matches:
                self._add_vulnerability(
                    name="Dangerous Function References",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    item_type="tool",
                    item_name=tool.name,
                    reason=f"Tool description references dangerous functions: {', '.join(dangerous_matches)}",
                    details={"patterns": dangerous_matches},
                    exploit_hint="Tool may use unsafe execution methods internally"
                )

    def _find_injectable_params(self, tool) -> list[str]:
        """Find parameters that look injectable."""
        injectable = []

        if tool.inputSchema and "properties" in tool.inputSchema:
            for param_name, param_info in tool.inputSchema["properties"].items():
                param_text = f"{param_name} {param_info.get('description', '')}"
                matches = self._check_text_patterns(
                    param_text,
                    self.INJECTABLE_PARAM_PATTERNS
                )
                if matches:
                    injectable.append(param_name)

        return injectable
