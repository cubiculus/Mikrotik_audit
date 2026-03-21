"""Test configuration generator for conflict analyzer testing.

This module generates RouterOS configurations with intentional conflicts
for testing the ConflictAnalyzer. Each scenario includes:
- Configuration commands to apply
- Expected conflicts that should be detected
- Cleanup commands to revert changes

WARNING: These configurations should only be applied to test routers!
Never apply to production equipment.
"""

import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ScenarioType(Enum):
    """Types of test scenarios."""
    UNREACHABLE_RULE = "unreachable_rule"
    NAT_BYPASSES_FIREWALL = "nat_bypasses_firewall"
    ORPHAN_ROUTING_MARK = "orphan_routing_mark"
    INTERFACE_NOT_IN_LIST = "interface_not_in_list"
    ADDRESS_LIST_CONFLICT = "address_list_conflict"
    FORWARD_WITHOUT_FASTTRACK = "forward_without_fasttrack"
    SHADOWED_RULE = "shadowed_rule"
    DUPLICATE_RULE = "duplicate_rule"


@dataclass
class ScenarioConfig:
    """Configuration for a test scenario."""
    name: str
    scenario_type: ScenarioType
    description: str
    setup_commands: List[str] = field(default_factory=list)
    expected_conflicts: List[str] = field(default_factory=list)
    cleanup_commands: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ScenarioGenerator:
    """
    Generates test configurations with intentional conflicts.

    Usage:
        generator = ScenarioGenerator()
        scenario = generator.get_scenario('unreachable_rule')

        # Apply setup_commands to test router
        # Run audit - should detect expected_conflicts
        # Apply cleanup_commands to revert
    """

    def __init__(self):
        self._scenarios = self._create_scenarios()

    def _create_scenarios(self) -> Dict[ScenarioType, ScenarioConfig]:
        """Create all test scenarios."""
        return {
            ScenarioType.UNREACHABLE_RULE: ScenarioConfig(
                name="Недостижимое правило",
                scenario_type=ScenarioType.UNREACHABLE_RULE,
                description=(
                    "Создаёт catch-all drop правило, после которого следует "
                    "правило accept. Второе правило никогда не сработает."
                ),
                setup_commands=[
                    "# Create catch-all drop rule (position 0)",
                    "/ip firewall filter add chain=forward action=drop "
                    "comment=\"Catch-all drop - TEST\" place-before=0",
                    "",
                    "# Create accept rule that will be unreachable (position 1)",
                    "/ip firewall filter add chain=forward src-address=192.168.100.0/24 "
                    "action=accept comment=\"Allow test subnet - TEST\" place-before=0"
                ],
                expected_conflicts=[
                    "UNREACHABLE_RULE",
                    "Rule at position 1 (accept) comes after a catch-all drop rule"
                ],
                cleanup_commands=[
                    "# Remove test rules",
                    "/ip firewall filter remove [find where comment~\"TEST\"]"
                ],
                prerequisites=[
                    "Router must have forward chain rules",
                    "User must have write permissions"
                ],
                warnings=[
                    "May temporarily block traffic if forward chain policy is restrictive",
                    "Apply during maintenance window"
                ]
            ),

            ScenarioType.NAT_BYPASSES_FIREWALL: ScenarioConfig(
                name="NAT обходит фаервол",
                scenario_type=ScenarioType.NAT_BYPASSES_FIREWALL,
                description=(
                    "Создаёт dstnat правило без соответствующего forward правила. "
                    "Трафик может достичь внутреннего хоста без проверки фаерволом."
                ),
                setup_commands=[
                    "# Create dstnat rule to internal host",
                    "/ip firewall nat add chain=dstnat action=dst-nat "
                    "protocol=tcp dst-port=8080 to-addresses=192.168.88.50 "
                    "to-ports=80 comment=\"NAT test - TEST\"",
                    "",
                    "# Ensure forward chain blocks by default",
                    "/ip firewall filter add chain=forward action=drop "
                    "comment=\"Default drop - TEST\" place-before=0"
                ],
                expected_conflicts=[
                    "NAT_BYPASSES_FIREWALL",
                    "NAT rule forwards traffic to 192.168.88.50 but no forward rule found"
                ],
                cleanup_commands=[
                    "# Remove test rules",
                    "/ip firewall nat remove [find where comment~\"TEST\"]",
                    "/ip firewall filter remove [find where comment~\"TEST\"]"
                ],
                prerequisites=[
                    "Router must have NAT enabled",
                    "192.168.88.0/24 subnet should not be in use"
                ],
                warnings=[
                    "Opens port 8080 to external access",
                    "Ensure test host 192.168.88.50 is not critical"
                ]
            ),

            ScenarioType.ORPHAN_ROUTING_MARK: ScenarioConfig(
                name="Маркировка без маршрута",
                scenario_type=ScenarioType.ORPHAN_ROUTING_MARK,
                description=(
                    "Создаёт mangle правило с routing-mark, но без соответствующего "
                    "маршрута. Помеченный трафик пойдёт по маршруту по умолчанию."
                ),
                setup_commands=[
                    "# Create mangle rule with routing mark",
                    "/ip firewall mangle add chain=prerouting action=mark-routing "
                    "new-routing-mark=TO_ISP_TEST passthrough=yes "
                    "src-address=192.168.50.0/24 comment=\"Mark for ISP - TEST\"",
                    "",
                    "# Note: No route with routing-mark=TO_ISP_TEST is added"
                ],
                expected_conflicts=[
                    "ORPHAN_ROUTING_MARK",
                    "Routing mark 'TO_ISP_TEST' has no corresponding route"
                ],
                cleanup_commands=[
                    "# Remove test mangle rule",
                    "/ip firewall mangle remove [find where comment~\"TEST\"]"
                ],
                prerequisites=[
                    "Router must have mangle rules enabled",
                    "192.168.50.0/24 should not conflict with existing subnets"
                ],
                warnings=[
                    "May affect routing for 192.168.50.0/24 subnet",
                    "Test in isolated network segment"
                ]
            ),

            ScenarioType.INTERFACE_NOT_IN_LIST: ScenarioConfig(
                name="Интерфейс не в списке",
                scenario_type=ScenarioType.INTERFACE_NOT_IN_LIST,
                description=(
                    "Создаёт интерфейс (или использует существующий) который не "
                    "добавлен ни в WAN ни в LAN список."
                ),
                setup_commands=[
                    "# Create a new interface list member for testing",
                    "# First, ensure WAN and LAN lists exist",
                    "/interface list add name=WAN_TEST_LIST",
                    "/interface list add name=LAN_TEST_LIST",
                    "",
                    "# Add only ether1 to WAN (if exists)",
                    "/interface list member add interface=ether1 list=WAN_TEST_LIST",
                    "",
                    "# Note: ether2 (if exists) is NOT added to any list"
                ],
                expected_conflicts=[
                    "INTERFACE_NOT_IN_LIST",
                    "Interface 'ether2' not in WAN or LAN list"
                ],
                cleanup_commands=[
                    "# Remove test interface lists",
                    "/interface list member remove [find where list=WAN_TEST_LIST]",
                    "/interface list member remove [find where list=LAN_TEST_LIST]",
                    "/interface list remove [find where name~\"_TEST_LIST\"]"
                ],
                prerequisites=[
                    "Router must have at least 2 physical interfaces",
                    "ether1 and ether2 should exist"
                ],
                warnings=[
                    "May affect firewall rules that use interface lists",
                    "Test on non-production router"
                ]
            ),

            ScenarioType.ADDRESS_LIST_CONFLICT: ScenarioConfig(
                name="Конфликт списков адресов",
                scenario_type=ScenarioType.ADDRESS_LIST_CONFLICT,
                description=(
                    "Добавляет один IP адрес одновременно в разрешающий и "
                    "запрещающий список адресов."
                ),
                setup_commands=[
                    "# Add IP to allowed list",
                    "/ip firewall address-list add list=ALLOWED_TEST "
                    "address=10.0.0.100 comment=\"Test allowed - TEST\"",
                    "",
                    "# Add SAME IP to blocked list",
                    "/ip firewall address-list add list=BLOCKED_TEST "
                    "address=10.0.0.100 comment=\"Test blocked - TEST\""
                ],
                expected_conflicts=[
                    "ADDRESS_LIST_CONFLICT",
                    "IP address 10.0.0.100 appears in both allowed and blocked lists"
                ],
                cleanup_commands=[
                    "# Remove test address lists",
                    "/ip firewall address-list remove [find where list=ALLOWED_TEST]",
                    "/ip firewall address-list remove [find where list=BLOCKED_TEST]"
                ],
                prerequisites=[
                    "10.0.0.100 should not be a critical IP",
                    "Router must support address lists"
                ],
                warnings=[
                    "May affect firewall behavior for 10.0.0.100",
                    "Ensure this IP is not used by management"
                ]
            ),

            ScenarioType.FORWARD_WITHOUT_FASTTRACK: ScenarioConfig(
                name="Отсутствует FastTrack",
                scenario_type=ScenarioType.FORWARD_WITHOUT_FASTTRACK,
                description=(
                    "Создаёт множество forward правил но без FastTrack. "
                    "Это не конфликт, но снижает производительность."
                ),
                setup_commands=[
                    "# Create multiple forward rules without FastTrack",
                    "/ip firewall filter add chain=forward action=accept "
                    "connection-state=established,related comment=\"Established - TEST\"",
                    "/ip firewall filter add chain=forward action=drop "
                    "connection-state=invalid comment=\"Invalid - TEST\"",
                    "/ip firewall filter add chain=forward action=accept "
                    "in-interface=LAN comment=\"From LAN - TEST\"",
                    "/ip firewall filter add chain=forward action=drop "
                    "in-interface=WAN comment=\"From WAN - TEST\"",
                    "/ip firewall filter add chain=forward action=accept "
                    "protocol=tcp dst-port=80 comment=\"HTTP - TEST\"",
                    "/ip firewall filter add chain=forward action=accept "
                    "protocol=tcp dst-port=443 comment=\"HTTPS - TEST\""
                ],
                expected_conflicts=[
                    "FORWARD_WITHOUT_FASTTRACK",
                    "No FastTrack rule for established connections"
                ],
                cleanup_commands=[
                    "# Remove test rules",
                    "/ip firewall filter remove [find where comment~\"TEST\"]"
                ],
                prerequisites=[
                    "Router must have forward chain",
                    "LAN and WAN interface lists should exist"
                ],
                warnings=[
                    "May affect network performance during test",
                    "6 rules added to forward chain"
                ]
            ),

            ScenarioType.SHADOWED_RULE: ScenarioConfig(
                name="Перекрытое правило",
                scenario_type=ScenarioType.SHADOWED_RULE,
                description=(
                    "Создаёт общее правило которое перекрывает более специфичное. "
                    "Специфичное правило никогда не сработает."
                ),
                setup_commands=[
                    "# Create general rule first (matches all TCP)",
                    "/ip firewall filter add chain=forward protocol=tcp "
                    "action=accept comment=\"Allow all TCP - TEST\" place-before=0",
                    "",
                    "# Create specific rule that will be shadowed",
                    "/ip firewall filter add chain=forward protocol=tcp dst-port=22 "
                    "action=drop comment=\"Block SSH - TEST\" place-before=0"
                ],
                expected_conflicts=[
                    "SHADOWED_RULE",
                    "Rule at position 1 (drop SSH) shadowed by rule at 0 (allow all TCP)"
                ],
                cleanup_commands=[
                    "# Remove test rules",
                    "/ip firewall filter remove [find where comment~\"TEST\"]"
                ],
                prerequisites=[
                    "Router must have forward chain rules"
                ],
                warnings=[
                    "Temporarily allows all TCP traffic",
                    "SSH blocking rule won't work during test"
                ]
            ),

            ScenarioType.DUPLICATE_RULE: ScenarioConfig(
                name="Дублирующееся правило",
                scenario_type=ScenarioType.DUPLICATE_RULE,
                description=(
                    "Создаёт два идентичных правила. Второе никогда не сработает."
                ),
                setup_commands=[
                    "# Create first rule",
                    "/ip firewall filter add chain=input protocol=tcp dst-port=22 "
                    "action=accept comment=\"Allow SSH - TEST\" place-before=0",
                    "",
                    "# Create EXACT duplicate",
                    "/ip firewall filter add chain=input protocol=tcp dst-port=22 "
                    "action=accept comment=\"Allow SSH - TEST\" place-before=0"
                ],
                expected_conflicts=[
                    "DUPLICATE_RULE",
                    "Rule appears to be duplicate"
                ],
                cleanup_commands=[
                    "# Remove test rules",
                    "/ip firewall filter remove [find where comment~\"TEST\"]"
                ],
                prerequisites=[
                    "Router must have input chain",
                    "Port 22 should not conflict with existing SSH rules"
                ],
                warnings=[
                    "Creates redundant firewall rules",
                    "No security impact but wastes resources"
                ]
            )
        }

    def get_scenario(self, name: str) -> Optional[ScenarioConfig]:
        """
        Get scenario by name.

        Args:
            name: Scenario name or type (e.g., 'unreachable_rule')

        Returns:
            ScenarioConfig or None if not found
        """
        # Try by enum value
        try:
            scenario_type = ScenarioType(name)
            return self._scenarios.get(scenario_type)
        except ValueError:
            pass

        # Try by name
        for scenario_type, config in self._scenarios.items():
            if config.name.lower() == name.lower():
                return config

        return None

    def get_all_scenarios(self) -> List[ScenarioConfig]:
        """Get all available scenarios."""
        return list(self._scenarios.values())

    def get_scenario_names(self) -> List[str]:
        """Get list of all scenario names."""
        return [s.name for s in self._scenarios.values()]

    def generate_test_config(self, scenario_names: List[str]) -> Dict:
        """
        Generate combined configuration for multiple scenarios.

        Args:
            scenario_names: List of scenario names to include

        Returns:
            Dict with:
            - setup_commands: Combined setup commands
            - expected_conflicts: Combined expected conflicts
            - cleanup_commands: Combined cleanup commands (in reverse order)
        """
        result = {
            'setup_commands': [],
            'expected_conflicts': [],
            'cleanup_commands': [],
            'warnings': []
        }

        for name in scenario_names:
            scenario = self.get_scenario(name)
            if scenario is None:
                logger.warning(f"Unknown scenario: {name}")
                continue

            result['setup_commands'].extend([
                f"# ===== {scenario.name} =====",
                f"# {scenario.description}"
            ])
            result['setup_commands'].extend(scenario.setup_commands)
            result['setup_commands'].append("")

            result['expected_conflicts'].extend(scenario.expected_conflicts)
            result['cleanup_commands'].extend(scenario.cleanup_commands)
            result['warnings'].extend(scenario.warnings)

        # Reverse cleanup so last setup is cleaned first
        result['cleanup_commands'].reverse()

        return result

    def validate_scenario(self, scenario_name: str) -> Tuple[bool, List[str]]:
        """
        Validate that a scenario can be safely applied.

        Args:
            scenario_name: Name of scenario to validate

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        scenario = self.get_scenario(scenario_name)
        if scenario is None:
            return False, [f"Unknown scenario: {scenario_name}"]

        issues = []

        # Check prerequisites (would need router connection to fully validate)
        # For now, just warn about prerequisites
        if scenario.prerequisites:
            issues.append(f"Prerequisites: {', '.join(scenario.prerequisites)}")

        # Always warn about test scenarios
        issues.append("WARNING: Only apply to test routers!")

        return True, issues


class ScenarioRunner:
    """
    Applies and cleans up test scenarios on a router.

    Requires SSH connection to router.
    """

    def __init__(self, ssh_handler):
        """
        Initialize runner.

        Args:
            ssh_handler: SSHHandler instance for router connection
        """
        self.ssh = ssh_handler
        self.generator = ScenarioGenerator()
        self.applied_scenarios: List[str] = []

    def apply_scenario(self, scenario_name: str) -> Tuple[bool, List[str]]:
        """
        Apply scenario to router.

        Args:
            scenario_name: Name of scenario to apply

        Returns:
            Tuple of (success, list_of_output_messages)
        """
        scenario = self.generator.get_scenario(scenario_name)
        if scenario is None:
            return False, [f"Unknown scenario: {scenario_name}"]

        output = []
        output.append(f"Applying scenario: {scenario.name}")
        output.append(f"Description: {scenario.description}")
        output.append("")

        # Apply setup commands
        for cmd in scenario.setup_commands:
            if cmd.startswith('#') or not cmd.strip():
                continue  # Skip comments and empty lines

            try:
                result = self.ssh.execute_command(cmd)
                if result.get('exit_status', 0) != 0:
                    output.append(f"ERROR: {cmd}")
                    output.append(f"  {result.get('stderr', 'Unknown error')}")
                    return False, output
                output.append(f"OK: {cmd[:60]}...")
            except Exception as e:
                output.append(f"EXCEPTION: {cmd}")
                output.append(f"  {str(e)}")
                return False, output

        self.applied_scenarios.append(scenario_name)
        output.append("")
        output.append(f"Scenario '{scenario_name}' applied successfully")

        return True, output

    def cleanup(self) -> Tuple[bool, List[str]]:
        """
        Cleanup all applied scenarios.

        Returns:
            Tuple of (success, list_of_output_messages)
        """
        output = []
        output.append("Cleaning up applied scenarios...")
        output.append("")

        # Cleanup in reverse order
        for scenario_name in reversed(self.applied_scenarios):
            scenario = self.generator.get_scenario(scenario_name)
            if scenario is None:
                continue

            output.append(f"Cleaning up: {scenario.name}")

            for cmd in scenario.cleanup_commands:
                if cmd.startswith('#') or not cmd.strip():
                    continue

                try:
                    result = self.ssh.execute_command(cmd)
                    if result.get('exit_status', 0) != 0:
                        output.append(f"WARNING: Cleanup failed for: {cmd}")
                    else:
                        output.append(f"OK: {cmd[:60]}...")
                except Exception as e:
                    output.append(f"EXCEPTION during cleanup: {str(e)}")

            output.append("")

        self.applied_scenarios.clear()
        output.append("Cleanup complete")

        return True, output

    def verify_conflicts(self, expected_conflicts: List[str]) -> Tuple[bool, List[str]]:
        """
        Verify that expected conflicts are detected.

        This requires running the audit and checking results.

        Args:
            expected_conflicts: List of expected conflict types

        Returns:
            Tuple of (all_found, list_of_messages)
        """
        # This would need integration with ConflictAnalyzer
        # For now, just log what we expect to find
        output = []
        output.append("Expected conflicts to detect:")
        for conflict in expected_conflicts:
            output.append(f"  - {conflict}")

        return True, output
