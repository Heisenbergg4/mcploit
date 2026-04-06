"""Prompt Injection vulnerability detector.

Detects both direct and indirect prompt injection vulnerabilities:
- Direct: User-controlled parameters passed to LLM without sanitization
- Indirect: Tools that process external content (documents, URLs, etc.)
- Hidden instructions in tool descriptions
"""

import re
from .base_detector import (
    BaseDetector,
    DetectorContext,
    Vulnerability,
    Severity,
    Confidence,
)


class PromptInjectionDetector(BaseDetector):
    """Detects prompt injection vulnerabilities."""

    name = "Prompt Injection Detector"
    description = "Detects direct and indirect prompt injection vulnerabilities"
    vulnerability_types = ["prompt_injection", "indirect_prompt_injection"]

    # Parameters that are strongly suggestive of prompt injection — only the
    # explicitly LLM-targeted ones.  Generic names like "text", "content",
    # "message", "name", "title", "description" appear on EVERY API MCP server
    # and flagging them creates massive noise without security value.
    INJECTABLE_PARAM_PATTERNS = [
        ("user_input", False),    # explicitly labelled user input
        ("prompt", False),        # explicitly a prompt field
        ("instruction", False),   # explicit instruction override vector
        ("system_prompt", False), # system prompt override
        ("llm_input", False),
        ("ai_input", False),
        ("model_input", False),
    ]

    # Patterns indicating document/content processing (indirect injection).
    # "url" alone fired on every HTTP tool; "process", "load", "import",
    # "web" are all common in legitimate tools.  Require at least 2 matches
    # for a MEDIUM finding, 3+ for HIGH (threshold enforced in _check_tool).
    INDIRECT_INJECTION_PATTERNS = [
        ("document", False),
        ("upload", False),
        ("read_file", False),
        ("download", False),
        ("extract", False),
        ("wikipedia", False),
        ("html", False),
        ("pdf", False),
        ("email", False),
        ("rss", False),
        (r"external\s+(content|document|url|data)", True),  # explicit external content
        (r"fetch\s+(url|page|content)", True),               # fetch + explicit target
    ]

    # Hidden instruction patterns in descriptions
    HIDDEN_INSTRUCTION_PATTERNS = [
        (r"<\s*IMPORTANT\s*>", True),
        (r"\[SYSTEM\s*(INSTRUCTION|OVERRIDE|COMMAND)\]", True),
        (r"ignore\s+(previous|all|above|prior|earlier)", True),
        (r"disregard\s+(previous|all|above|instructions)", True),
        (r"forget\s+(everything|all|previous)", True),
        (r"new\s+instructions?:", True),
        (r"actually,?\s+(do|perform|execute)", True),
        (r"instead,?\s+(do|perform|you\s+should)", True),
        (r"override", False),
        (r"bypass", False),
        (r"<!-{2,}", True),  # HTML comments
        (r"\x00", True),  # Null bytes
        (r"\\u0000", True),  # Unicode null
    ]

    # Resource URI patterns that suggest injectable content
    INJECTABLE_RESOURCE_PATTERNS = [
        (r"notes://\{", True),  # Template with user parameter
        (r"://\{user", True),
        (r"://\{.*_id\}", True),
        (r"://\{input", True),
        (r"://\{query", True),
    ]

    def detect(self, context: DetectorContext) -> list[Vulnerability]:
        """Detect prompt injection vulnerabilities."""
        self.vulnerabilities = []

        # Check tools
        for tool in context.tools:
            self._check_tool_for_injection(tool)

        # Check resources
        for resource in context.resources:
            self._check_resource_for_injection(resource)

        # Check prompts
        for prompt in context.prompts:
            self._check_prompt_for_injection(prompt)

        return self.vulnerabilities

    def _check_tool_for_injection(self, tool):
        """Check a tool for prompt injection vulnerabilities."""
        tool_text = self._get_tool_text(tool)

        # Check for hidden instructions in description
        if tool.description:
            hidden_matches = self._check_text_patterns(
                tool.description,
                self.HIDDEN_INSTRUCTION_PATTERNS
            )
            if hidden_matches:
                self._add_vulnerability(
                    name="Hidden Instructions in Tool Description",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    item_type="tool",
                    item_name=tool.name,
                    reason=f"Tool description contains hidden instruction patterns: {', '.join(hidden_matches)}",
                    details={"patterns": hidden_matches, "description": tool.description},
                    exploit_hint="The tool description may contain instructions that manipulate LLM behavior"
                )

        # Check for indirect injection (document/content processing).
        # Require ≥2 matches for MEDIUM, ≥3 for HIGH — single matches like
        # "upload" or "download" alone are far too common on legitimate tools.
        indirect_matches = self._check_text_patterns(
            tool_text,
            self.INDIRECT_INJECTION_PATTERNS
        )
        if len(indirect_matches) >= 2:
            severity = Severity.HIGH if len(indirect_matches) >= 3 else Severity.MEDIUM
            confidence = Confidence.HIGH if len(indirect_matches) >= 3 else Confidence.MEDIUM

            self._add_vulnerability(
                name="Indirect Prompt Injection Risk",
                severity=severity,
                confidence=confidence,
                item_type="tool",
                item_name=tool.name,
                reason=f"Tool processes external content which may contain embedded instructions: {', '.join(indirect_matches)}",
                details={"patterns": indirect_matches},
                exploit_hint="Embed malicious instructions in uploaded documents or fetched content"
            )

        # Check for injectable parameters — only flag explicitly LLM-targeted params.
        # Common params like "text", "content", "message", "name", "description" are
        # present on every API tool and are not security-meaningful without context.
        if tool.inputSchema and "properties" in tool.inputSchema:
            for param_name, param_info in tool.inputSchema["properties"].items():
                param_text = f"{param_name} {param_info.get('description', '')}"
                injectable_matches = self._check_text_patterns(
                    param_text,
                    self.INJECTABLE_PARAM_PATTERNS
                )
                if injectable_matches:
                    param_type = param_info.get("type", "")
                    if param_type == "string":
                        self._add_vulnerability(
                            name="Direct Prompt Injection Vector",
                            severity=Severity.HIGH,   # escalated: explicit LLM input param
                            confidence=Confidence.HIGH,
                            item_type="tool",
                            item_name=tool.name,
                            reason=f"Parameter '{param_name}' is explicitly labelled as LLM/AI input",
                            details={
                                "parameter": param_name,
                                "type": param_type,
                                "patterns": injectable_matches
                            },
                            exploit_hint=f"Inject LLM instructions via the '{param_name}' parameter"
                        )

    def _check_resource_for_injection(self, resource):
        """Check a resource for prompt injection vulnerabilities."""
        uri = str(resource.uri)
        resource_text = self._get_resource_text(resource)

        # Check for injectable URI patterns (templated with user input)
        injectable_matches = self._check_text_patterns(
            uri,
            self.INJECTABLE_RESOURCE_PATTERNS
        )
        if injectable_matches:
            self._add_vulnerability(
                name="Injectable Resource URI",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="resource",
                item_name=uri,
                reason=f"Resource URI contains injectable template parameters",
                details={"uri": uri, "patterns": injectable_matches},
                exploit_hint="Inject LLM instructions via the URI parameter"
            )

        # Check description for hidden instructions
        if resource.description:
            hidden_matches = self._check_text_patterns(
                resource.description,
                self.HIDDEN_INSTRUCTION_PATTERNS
            )
            if hidden_matches:
                self._add_vulnerability(
                    name="Hidden Instructions in Resource",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    item_type="resource",
                    item_name=uri,
                    reason=f"Resource description contains hidden instruction patterns: {', '.join(hidden_matches)}",
                    details={"patterns": hidden_matches},
                    exploit_hint="Resource may manipulate LLM behavior through hidden instructions"
                )

    def _check_prompt_for_injection(self, prompt):
        """Check a prompt for injection vulnerabilities."""
        prompt_text = self._get_prompt_text(prompt)

        # Check for hidden instructions
        if prompt.description:
            hidden_matches = self._check_text_patterns(
                prompt.description,
                self.HIDDEN_INSTRUCTION_PATTERNS
            )
            if hidden_matches:
                self._add_vulnerability(
                    name="Hidden Instructions in Prompt",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    item_type="prompt",
                    item_name=prompt.name,
                    reason=f"Prompt contains hidden instruction patterns: {', '.join(hidden_matches)}",
                    details={"patterns": hidden_matches},
                    exploit_hint="Prompt may manipulate LLM behavior"
                )

        # Check for injectable arguments
        if prompt.arguments:
            for arg in prompt.arguments:
                arg_text = f"{arg.name} {getattr(arg, 'description', '')}"
                injectable_matches = self._check_text_patterns(
                    arg_text,
                    self.INJECTABLE_PARAM_PATTERNS
                )
                if injectable_matches:
                    self._add_vulnerability(
                        name="Injectable Prompt Argument",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        item_type="prompt",
                        item_name=prompt.name,
                        reason=f"Prompt argument '{arg.name}' may allow injection",
                        details={"argument": arg.name, "patterns": injectable_matches},
                        exploit_hint=f"Inject instructions via the '{arg.name}' argument"
                    )
