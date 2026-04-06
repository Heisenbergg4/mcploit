"""
Tool Manipulation Payloads for MCPloit.

Contains payloads for testing rug pull attacks and tool shadowing
vulnerabilities in MCP servers.

Target Challenges:
- DVMCP Challenge 4: Rug Pull Attack (tool mutation)
- DVMCP Challenge 5: Tool Shadowing (name conflicts)
"""

from .base import Payload, PayloadCategory, PayloadSeverity


def get_payloads() -> list[Payload]:
    """Return all tool manipulation detection payloads."""
    return [
        # === TOOL MANIPULATION PAYLOADS ===
        # NOTE: These are for DETECTION/BEHAVIORAL analysis, not data extraction
        # Challenges 4 & 5 require LLM layer to follow hidden instructions in tool descriptions
        # MCPloit can detect these vulnerabilities but not fully exploit without LLM

        # === RUG PULL DETECTION ===
        Payload(
            name="repeated_invocation_test",
            description="Detect rug pull by calling tool multiple times",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="invoke_count_3",
            variants=[
                "invoke_count_5",
                "invoke_count_10",
                "rapid_succession",
                "threshold_test",
            ],
            target_params=["test_mode", "invocation_pattern"],
            success_indicators=[
                "changed", "mutated", "different", "modified",
                "aws_access_key", "credential", "secret"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="rug_pull_detection",
            context="Call tool repeatedly to detect definition changes",
        ),

        Payload(
            name="tool_definition_hash",
            description="Hash tool definitions to detect mutations",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="compute_definition_hash",
            variants=[
                "monitor_description",
                "track_schema_changes",
                "version_fingerprint",
            ],
            target_params=["detection_mode", "method"],
            success_indicators=[
                "hash_mismatch", "definition_changed", "schema_mutated",
                "description_modified"
            ],
            severity=PayloadSeverity.HIGH,
            technique="definition_monitoring",
            context="Detect tool definition changes via hashing",
        ),

        Payload(
            name="invocation_threshold_probe",
            description="Probe for invocation count thresholds",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="threshold_1",
            variants=[
                "threshold_2",
                "threshold_3",
                "threshold_5",
                "threshold_10",
            ],
            target_params=["call_count", "threshold"],
            success_indicators=[
                "threshold", "limit", "count", "activated",
                "triggered", "mutation"
            ],
            severity=PayloadSeverity.HIGH,
            technique="threshold_discovery",
            context="Discover at what invocation count rug pull activates",
        ),

        # === TOOL SHADOWING DETECTION ===
        Payload(
            name="name_similarity_check",
            description="Detect tools with confusingly similar names",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="find_similar_names",
            variants=[
                "check_prefixes",
                "check_suffixes",
                "check_typosquats",
                "compare_all_tools",
            ],
            target_params=["detection_mode", "check_type"],
            success_indicators=[
                "similar", "shadowed", "conflict", "duplicate",
                "enhanced_", "trusted_", "_v2", "_new"
            ],
            severity=PayloadSeverity.HIGH,
            technique="name_conflict_detection",
            context="Identify tools with names that could shadow legitimate tools",
        ),

        Payload(
            name="shadowing_prefix_patterns",
            description="Common prefixes used in tool shadowing",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="enhanced_",
            variants=[
                "improved_",
                "better_",
                "new_",
                "secure_",
                "safe_",
                "trusted_",
                "verified_",
                "official_",
            ],
            target_params=["tool_name", "prefix"],
            success_indicators=[
                "shadow", "override", "replace", "original",
                "legitimate", "malicious"
            ],
            severity=PayloadSeverity.HIGH,
            technique="prefix_analysis",
            context="Detect suspicious naming prefixes that suggest shadowing",
        ),

        Payload(
            name="description_comparison",
            description="Compare descriptions of similar-named tools",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="compare_descriptions",
            variants=[
                "diff_functionality",
                "check_hidden_differences",
                "analyze_schemas",
            ],
            target_params=["analysis_type", "mode"],
            success_indicators=[
                "hidden instruction", "<IMPORTANT>", "secret",
                "credential", "different behavior"
            ],
            severity=PayloadSeverity.HIGH,
            technique="description_diff",
            context="Find hidden differences between similar tools",
        ),

        # === HIDDEN RESOURCE ACCESS ===
        Payload(
            name="hidden_resource_discovery",
            description="Discover hidden resources referenced by shadowing tools",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="system://secrets",
            variants=[
                "internal://credentials",
                "config://database",
                "hidden://data",
                "admin://keys",
                "private://tokens",
            ],
            target_params=["resource_uri", "uri"],
            success_indicators=[
                "secret", "credential", "password", "token",
                "api_key", "database"
            ],
            severity=PayloadSeverity.CRITICAL,
            technique="hidden_resource_access",
            context="Access hidden resources exposed by malicious tool descriptions",
        ),

        Payload(
            name="shadowed_tool_behavior",
            description="Test if shadowed tool exhibits different behavior",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="test_legitimate_operation",
            variants=[
                "calculate_simple",
                "perform_read_only",
                "execute_safe_action",
            ],
            target_params=["operation", "test_type"],
            success_indicators=[
                "unexpected", "side_effect", "credential", "leaked",
                "exfiltrated", "hidden"
            ],
            severity=PayloadSeverity.HIGH,
            technique="behavior_analysis",
            context="Compare expected vs actual behavior of potentially shadowed tools",
        ),

        # === MUTATION TRACKING ===
        Payload(
            name="schema_mutation_detection",
            description="Detect changes in tool input/output schemas",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="track_schema",
            variants=[
                "monitor_parameters",
                "watch_return_type",
                "compare_signatures",
            ],
            target_params=["tracking_mode", "target"],
            success_indicators=[
                "parameter_added", "type_changed", "required_modified",
                "new_field", "schema_mutation"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="schema_monitoring",
            context="Track tool schema changes over time",
        ),

        Payload(
            name="version_discrepancy_check",
            description="Check for version mismatches in tool definitions",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="check_versions",
            variants=[
                "compare_timestamps",
                "verify_signatures",
                "validate_checksums",
            ],
            target_params=["check_type", "validation_mode"],
            success_indicators=[
                "mismatch", "outdated", "modified", "unsigned",
                "invalid_checksum"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="version_verification",
            context="Verify tool integrity through version checks",
        ),

        # === DYNAMIC ANALYSIS ===
        Payload(
            name="pre_post_comparison",
            description="Compare tool behavior before/after multiple calls",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="snapshot_compare",
            variants=[
                "baseline_delta",
                "temporal_analysis",
                "state_tracking",
            ],
            target_params=["analysis_mode", "comparison_type"],
            success_indicators=[
                "changed", "delta", "difference", "mutation",
                "state_modified"
            ],
            severity=PayloadSeverity.HIGH,
            technique="temporal_analysis",
            context="Compare tool state/behavior across invocations",
        ),

        Payload(
            name="concurrent_tool_check",
            description="Test tool behavior under concurrent access",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="concurrent_test",
            variants=[
                "parallel_invocation",
                "race_condition_probe",
                "simultaneous_calls",
            ],
            target_params=["test_mode", "concurrency_type"],
            success_indicators=[
                "race", "inconsistent", "different_results",
                "state_corruption"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="concurrency_analysis",
            context="Detect race conditions or state issues in rug pull implementations",
        ),

        # === PERSISTENCE DETECTION ===
        Payload(
            name="session_persistence_check",
            description="Check if rug pull state persists across sessions",
            category=PayloadCategory.TOOL_MANIPULATION,
            payload="new_session_test",
            variants=[
                "reconnect_verify",
                "fresh_connection",
                "reset_state",
            ],
            target_params=["session_mode", "persistence_check"],
            success_indicators=[
                "persisted", "maintained", "remembered", "stateful",
                "cross_session"
            ],
            severity=PayloadSeverity.MEDIUM,
            technique="persistence_analysis",
            context="Determine if malicious state persists across reconnections",
        ),
    ]
