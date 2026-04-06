"""
Payload Manager for MCPloit.

Central manager for loading, organizing, and querying payloads
across all vulnerability categories.
"""

from typing import Optional

from .base import Payload, PayloadSeverity
from . import (
    prompt_injection,
    tool_poisoning,
    path_traversal,
    code_execution,
    token_theft,
    tool_manipulation,
    secrets_exposure,
)


class PayloadManager:
    """
    Manages all payloads across vulnerability categories.

    Provides methods to load, filter, and retrieve payloads
    for security testing.

    Usage:
        manager = PayloadManager()

        # Get all payloads for a category
        pi_payloads = manager.get_payloads('prompt_injection')

        # Get payloads by severity
        critical = manager.get_by_severity(PayloadSeverity.CRITICAL)

        # Get payloads for a specific parameter
        host_payloads = manager.get_for_param('host')

        # Search payloads
        results = manager.search('credential')
    """

    # Map category names to modules
    _CATEGORY_MODULES = {
        'prompt_injection': prompt_injection,
        'tool_poisoning': tool_poisoning,
        'path_traversal': path_traversal,
        'code_execution': code_execution,
        'token_theft': token_theft,
        'tool_manipulation': tool_manipulation,
        'secrets_exposure': secrets_exposure,
    }

    # Aliases for category names
    _CATEGORY_ALIASES = {
        'pi': 'prompt_injection',
        'injection': 'prompt_injection',
        'poisoning': 'tool_poisoning',
        'traversal': 'path_traversal',
        'pt': 'path_traversal',
        'lfi': 'path_traversal',
        'rce': 'code_execution',
        'exec': 'code_execution',
        'command': 'code_execution',
        'token': 'token_theft',
        'theft': 'token_theft',
        'session': 'token_theft',
        'manipulation': 'tool_manipulation',
        'rug_pull': 'tool_manipulation',
        'shadowing': 'tool_manipulation',
        'secrets': 'secrets_exposure',
        'credentials': 'secrets_exposure',
        'pii': 'secrets_exposure',
    }

    def __init__(self):
        """Initialize the PayloadManager and load all payloads."""
        self._payloads: dict[str, list[Payload]] = {}
        self._all_payloads: list[Payload] = []
        self._load_all_payloads()

    def _load_all_payloads(self) -> None:
        """Load payloads from all category modules."""
        for category_name, module in self._CATEGORY_MODULES.items():
            payloads = module.get_payloads()
            self._payloads[category_name] = payloads
            self._all_payloads.extend(payloads)

    def _resolve_category(self, category: str) -> str:
        """Resolve category name, handling aliases."""
        category = category.lower().strip()
        return self._CATEGORY_ALIASES.get(category, category)

    def get_payloads(self, category: str) -> list[Payload]:
        """
        Get all payloads for a specific category.

        Args:
            category: Category name or alias (e.g., 'prompt_injection', 'pi', 'rce')

        Returns:
            List of payloads for the category
        """
        resolved = self._resolve_category(category)
        return self._payloads.get(resolved, [])

    def get_all_payloads(self) -> list[Payload]:
        """Get all payloads across all categories."""
        return self._all_payloads.copy()

    def get_by_severity(self, severity: PayloadSeverity) -> list[Payload]:
        """
        Get all payloads of a specific severity level.

        Args:
            severity: PayloadSeverity enum value

        Returns:
            List of payloads matching the severity
        """
        return [p for p in self._all_payloads if p.severity == severity]

    def get_by_technique(self, technique: str) -> list[Payload]:
        """
        Get all payloads using a specific technique.

        Args:
            technique: Technique name (e.g., 'instruction_override', 'command_injection')

        Returns:
            List of payloads using the technique
        """
        technique = technique.lower()
        return [p for p in self._all_payloads if technique in p.technique.lower()]

    def get_for_param(self, param_name: str) -> list[Payload]:
        """
        Get payloads that can target a specific parameter.

        Args:
            param_name: Parameter name (e.g., 'host', 'file', 'content')

        Returns:
            List of payloads that can target the parameter
        """
        return [p for p in self._all_payloads if p.matches_param(param_name)]

    def search(self, query: str) -> list[Payload]:
        """
        Search payloads by name, description, or payload content.

        Args:
            query: Search string (case-insensitive)

        Returns:
            List of matching payloads
        """
        query = query.lower()
        results = []

        for payload in self._all_payloads:
            if (query in payload.name.lower() or
                query in payload.description.lower() or
                query in payload.payload.lower() or
                query in payload.technique.lower() or
                any(query in v.lower() for v in payload.variants)):
                results.append(payload)

        return results

    def get_categories(self) -> list[str]:
        """Get list of available category names."""
        return list(self._CATEGORY_MODULES.keys())

    def get_category_stats(self) -> dict[str, int]:
        """Get payload count per category."""
        return {name: len(payloads) for name, payloads in self._payloads.items()}

    def get_severity_stats(self) -> dict[str, int]:
        """Get payload count per severity level."""
        stats = {}
        for severity in PayloadSeverity:
            count = len([p for p in self._all_payloads if p.severity == severity])
            stats[severity.value] = count
        return stats

    def get_total_count(self) -> int:
        """Get total number of payloads."""
        return len(self._all_payloads)

    def get_random(self,
                   category: Optional[str] = None,
                   severity: Optional[PayloadSeverity] = None,
                   count: int = 1) -> list[Payload]:
        """
        Get random payloads, optionally filtered.

        Args:
            category: Optional category filter
            severity: Optional severity filter
            count: Number of payloads to return

        Returns:
            List of random payloads
        """
        import random

        candidates = self._all_payloads

        if category:
            resolved = self._resolve_category(category)
            candidates = [p for p in candidates if p.category.value == resolved]

        if severity:
            candidates = [p for p in candidates if p.severity == severity]

        return random.sample(candidates, min(count, len(candidates)))

    def to_dict(self) -> dict:
        """
        Export all payloads as a dictionary.

        Returns:
            Dictionary with categories as keys and payload lists as values
        """
        return {
            category: [p.to_dict() for p in payloads]
            for category, payloads in self._payloads.items()
        }

    def summary(self) -> str:
        """
        Get a formatted summary of the payload library.

        Returns:
            Multi-line summary string
        """
        lines = [
            "MCPloit Payload Library Summary",
            "=" * 40,
            f"Total Payloads: {self.get_total_count()}",
            "",
            "By Category:",
        ]

        for category, count in sorted(self.get_category_stats().items()):
            lines.append(f"  {category}: {count}")

        lines.extend(["", "By Severity:"])

        for severity, count in sorted(self.get_severity_stats().items()):
            lines.append(f"  {severity}: {count}")

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"PayloadManager(total={self.get_total_count()}, categories={len(self._payloads)})"
