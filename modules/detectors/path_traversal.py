"""Path Traversal vulnerability detector.

Detects file system access vulnerabilities:
- Unrestricted file read/write operations
- Path traversal through user-controlled parameters
- Access to sensitive directories
- Excessive file permissions
"""

from .base_detector import (
    BaseDetector,
    DetectorContext,
    Vulnerability,
    Severity,
    Confidence,
)


class PathTraversalDetector(BaseDetector):
    """Detects path traversal and file access vulnerabilities."""

    name = "Path Traversal Detector"
    description = "Detects file system access and path traversal vulnerabilities"
    vulnerability_types = ["path_traversal", "excessive_permissions", "file_access"]

    # File operation tool name patterns
    FILE_OPERATION_PATTERNS = [
        ("read_file", False),
        ("write_file", False),
        ("delete_file", False),
        ("list_files", False),
        ("list_directory", False),
        ("search_files", False),
        ("get_file", False),
        ("save_file", False),
        ("open_file", False),
        ("create_file", False),
        ("copy_file", False),
        ("move_file", False),
        ("rename_file", False),
        ("file_read", False),
        ("file_write", False),
        ("filesystem", False),
        ("workspace", False),
        ("directory", False),
        ("file_manager", False),
        ("filemanager", False),
        ("file manager", False),
        (r"can\s+read", True),
        (r"can\s+write", True),
        (r"can\s+delete", True),
        ("read, write", False),
        ("write, delete", False),
        ("read and write", False),
    ]

    # Path parameter patterns
    PATH_PARAM_PATTERNS = [
        ("path", False),
        ("file", False),
        ("filename", False),
        ("filepath", False),
        ("directory", False),
        ("dir", False),
        ("folder", False),
        ("location", False),
        ("target", False),
        ("source", False),
        ("dest", False),
        ("destination", False),
    ]

    # Sensitive path indicators
    SENSITIVE_PATH_PATTERNS = [
        (r"/etc/", True),
        (r"/root/", True),
        (r"/home/", True),
        (r"/var/", True),
        (r"/tmp/", True),
        (r"/proc/", True),
        (r"/sys/", True),
        (r"\.env", True),
        (r"\.ssh/", True),
        (r"\.aws/", True),
        (r"\.git/", True),
        (r"config", False),
        (r"secret", False),
        (r"credential", False),
        (r"password", False),
        (r"private", False),
    ]

    # Path traversal indicators in descriptions
    TRAVERSAL_INDICATORS = [
        ("any file", False),
        ("any path", False),
        ("absolute path", False),
        ("full path", False),
        ("anywhere", False),
        ("no restriction", False),
        ("unrestricted", False),
        ("outside", False),
        ("system file", False),
    ]

    # File:// URI patterns
    FILE_URI_PATTERNS = [
        (r"file://", True),
        (r"file:///", True),
    ]

    def detect(self, context: DetectorContext) -> list[Vulnerability]:
        """Detect path traversal vulnerabilities."""
        self.vulnerabilities = []

        # Check tools
        for tool in context.tools:
            self._check_tool_for_traversal(tool)

        # Check resources
        for resource in context.resources:
            self._check_resource_for_traversal(resource)

        return self.vulnerabilities

    def _check_tool_for_traversal(self, tool):
        """Check a tool for path traversal vulnerabilities."""
        tool_text = self._get_tool_text(tool)

        # Check if tool performs file operations
        file_op_matches = self._check_text_patterns(
            tool_text,
            self.FILE_OPERATION_PATTERNS
        )

        if not file_op_matches:
            return

        # This is a file operation tool - check for vulnerabilities

        # Check for path parameters
        path_params = []
        if tool.inputSchema and "properties" in tool.inputSchema:
            for param_name, param_info in tool.inputSchema["properties"].items():
                param_text = f"{param_name} {param_info.get('description', '')}"
                if self._check_text_patterns(param_text, self.PATH_PARAM_PATTERNS):
                    path_params.append(param_name)

        # Check for traversal indicators in description
        traversal_matches = []
        if tool.description:
            traversal_matches = self._check_text_patterns(
                tool.description,
                self.TRAVERSAL_INDICATORS
            )

        # Check for sensitive path mentions
        sensitive_matches = self._check_text_patterns(
            tool_text,
            self.SENSITIVE_PATH_PATTERNS
        )

        # Determine severity based on findings
        if traversal_matches or sensitive_matches:
            # High confidence path traversal
            severity = Severity.CRITICAL if sensitive_matches else Severity.HIGH
            confidence = Confidence.HIGH

            self._add_vulnerability(
                name="Path Traversal Vulnerability",
                severity=severity,
                confidence=confidence,
                item_type="tool",
                item_name=tool.name,
                reason=f"File operation tool with unrestricted path access. Indicators: {', '.join(traversal_matches + sensitive_matches)}",
                details={
                    "file_operations": file_op_matches,
                    "path_parameters": path_params,
                    "traversal_indicators": traversal_matches,
                    "sensitive_paths": sensitive_matches
                },
                exploit_hint="Use ../ sequences or absolute paths to access files outside intended directory"
            )
        elif path_params:
            # File operation with path parameters - potential vulnerability
            self._add_vulnerability(
                name="Potential Path Traversal",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                item_type="tool",
                item_name=tool.name,
                reason=f"File operation tool accepts path parameters: {', '.join(path_params)}",
                details={
                    "file_operations": file_op_matches,
                    "path_parameters": path_params
                },
                exploit_hint="Test path parameters with ../ sequences and absolute paths"
            )

        # Check for excessive permissions (read + write + delete)
        has_read = any("read" in m.lower() for m in file_op_matches)
        has_write = any("write" in m.lower() or "save" in m.lower() or "create" in m.lower() for m in file_op_matches)
        has_delete = any("delete" in m.lower() for m in file_op_matches)

        if has_read and has_write:
            self._add_vulnerability(
                name="Excessive File Permissions",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                item_type="tool",
                item_name=tool.name,
                reason="Tool provides both read and write access to files",
                details={
                    "permissions": {
                        "read": has_read,
                        "write": has_write,
                        "delete": has_delete
                    }
                },
                exploit_hint="Combine read and write access to exfiltrate and modify sensitive files"
            )

    def _check_resource_for_traversal(self, resource):
        """Check a resource for path traversal vulnerabilities."""
        uri = str(resource.uri)

        # Check for file:// URIs
        file_uri_matches = self._check_text_patterns(uri, self.FILE_URI_PATTERNS)

        if file_uri_matches:
            # Check for sensitive paths in URI
            sensitive_matches = self._check_text_patterns(uri, self.SENSITIVE_PATH_PATTERNS)

            if sensitive_matches:
                self._add_vulnerability(
                    name="Sensitive File Resource",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    item_type="resource",
                    item_name=uri,
                    reason=f"Resource exposes sensitive file path: {', '.join(sensitive_matches)}",
                    details={"uri": uri, "sensitive_patterns": sensitive_matches},
                    exploit_hint="Access this resource to read sensitive system files"
                )
            else:
                self._add_vulnerability(
                    name="File System Resource",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    item_type="resource",
                    item_name=uri,
                    reason="Resource uses file:// URI scheme allowing file system access",
                    details={"uri": uri},
                    exploit_hint="Test if path can be manipulated to access other files"
                )

        # Check for templated file resources
        if "{" in uri and "}" in uri:
            path_matches = self._check_text_patterns(uri, self.PATH_PARAM_PATTERNS)
            if path_matches or "file" in uri.lower():
                self._add_vulnerability(
                    name="Templated File Resource",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    item_type="resource",
                    item_name=uri,
                    reason="Resource URI contains templated path parameter",
                    details={"uri": uri, "patterns": path_matches},
                    exploit_hint="Inject path traversal sequences into the template parameter"
                )
