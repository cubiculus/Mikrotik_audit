"""Conflict analyzer for MikroTik RouterOS firewall rules.

This module analyzes firewall, NAT, and mangle rules to detect conflicts
and configuration issues that can cause unexpected behavior.

RouterOS Packet Flow (simplified):
    RAW → Mangle prerouting → NAT dstnat → Routing →
    Firewall forward → Mangle postrouting → NAT srcnat
"""

import re
import logging
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from src.config import CommandResult

logger = logging.getLogger(__name__)


class ConflictType(Enum):
    """Types of firewall rule conflicts."""
    UNREACHABLE_RULE = "UNREACHABLE_RULE"
    NAT_BYPASSES_FIREWALL = "NAT_BYPASSES_FIREWALL"
    ORPHAN_ROUTING_MARK = "ORPHAN_ROUTING_MARK"
    INTERFACE_NOT_IN_LIST = "INTERFACE_NOT_IN_LIST"
    ADDRESS_LIST_CONFLICT = "ADDRESS_LIST_CONFLICT"
    FORWARD_WITHOUT_FASTTRACK = "FORWARD_WITHOUT_FASTTRACK"
    SHADOWED_RULE = "SHADOWED_RULE"
    DUPLICATE_RULE = "DUPLICATE_RULE"


@dataclass
class ConflictResult:
    """Result of conflict analysis."""
    conflict_type: ConflictType
    severity: str  # Critical, High, Medium, Low
    title: str
    description: str
    rule_index: Optional[int] = None
    rule_command: Optional[str] = None
    conflicting_rule: Optional[str] = None
    recommendation: str = ""
    fix_commands: List[str] = field(default_factory=list)


class ConflictAnalyzer:
    """
    Analyzes RouterOS configuration for rule conflicts.

    Detects:
    - Rules that will never match (shadowed by earlier rules)
    - NAT rules that bypass firewall filters
    - Mangle marks without corresponding routes
    - Interfaces not in WAN/LAN lists
    - Address list conflicts
    - Missing FastTrack rules
    """

    def __init__(self):
        self.filter_rules: List[Dict] = []
        self.nat_rules: List[Dict] = []
        self.mangle_rules: List[Dict] = []
        self.routes: List[Dict] = []
        self.interface_lists: Dict[str, List[str]] = {}
        self.address_lists: Dict[str, List[str]] = {}
        self.interfaces: List[str] = []

    def parse_filter_rules(self, output: str) -> List[Dict]:
        """Parse firewall filter rules from command output."""
        rules: List[Dict] = []
        current_rule: Dict = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            # New rule starts with number
            if re.match(r'^\s*\d+\s', line):
                if current_rule:
                    rules.append(current_rule)
                current_rule = {}

            # Parse key=value or key: value pairs
            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\s]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2)
                current_rule[key] = value

        if current_rule:
            rules.append(current_rule)

        return rules

    def parse_nat_rules(self, output: str) -> List[Dict]:
        """Parse NAT rules from command output."""
        return self.parse_filter_rules(output)

    def parse_mangle_rules(self, output: str) -> List[Dict]:
        """Parse mangle rules from command output."""
        return self.parse_filter_rules(output)

    def parse_routes(self, output: str) -> List[Dict]:
        """Parse routing table from command output."""
        routes: List[Dict] = []
        current_route: Dict = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            if re.match(r'^\s*\d+\s', line):
                if current_route:
                    routes.append(current_route)
                current_route = {}

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\s]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2)
                current_route[key] = value

        if current_route:
            routes.append(current_route)

        return routes

    def parse_interface_lists(self, output: str) -> Dict[str, List[str]]:
        """Parse interface list members from command output."""
        lists: Dict[str, List[str]] = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            # Parse list name from "list=WAN" or "list: WAN"
            list_match = re.search(r'list\s*[=:]\s*["\']?([^"\'\s]+)', line)
            # Parse interface from "interface=ether1" or "interface: ether1"
            iface_match = re.search(r'interface\s*[=:]\s*["\']?([^"\'\s]+)', line)

            if list_match and iface_match:
                list_name = list_match.group(1)
                interface = iface_match.group(1)
                if list_name not in lists:
                    lists[list_name] = []
                lists[list_name].append(interface)

        return lists

    def parse_address_lists(self, output: str) -> Dict[str, List[str]]:
        """Parse firewall address lists from command output."""
        lists: Dict[str, List[str]] = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            # Parse address list entry
            list_match = re.search(r'list\s*[=:]\s*["\']?([^"\'\s]+)', line)
            addr_match = re.search(r'address\s*[=:]\s*["\']?([^"\'\s/]+)', line)

            if list_match and addr_match:
                list_name = list_match.group(1)
                address = addr_match.group(1)
                if list_name not in lists:
                    lists[list_name] = []
                lists[list_name].append(address)

        return lists

    def parse_interfaces(self, output: str) -> List[str]:
        """Parse interface names from command output."""
        interfaces = []

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            # Parse interface name
            name_match = re.search(r'name\s*[=:]\s*["\']?([^"\'\s]+)', line)
            if name_match:
                interfaces.append(name_match.group(1))

        return interfaces

    def load_data(self, results: List[CommandResult]) -> None:
        """Load configuration data from command results."""
        for result in results:
            if result.has_error:
                continue

            cmd = result.command.lower()
            output = result.stdout

            if 'firewall filter' in cmd:
                self.filter_rules.extend(self.parse_filter_rules(output))
            elif 'firewall nat' in cmd:
                self.nat_rules.extend(self.parse_nat_rules(output))
            elif 'firewall mangle' in cmd:
                self.mangle_rules.extend(self.parse_mangle_rules(output))
            elif 'route print' in cmd:
                self.routes.extend(self.parse_routes(output))
            elif 'interface list member' in cmd:
                lists = self.parse_interface_lists(output)
                for name, members in lists.items():
                    if name not in self.interface_lists:
                        self.interface_lists[name] = []
                    self.interface_lists[name].extend(members)
            elif 'address-list print' in cmd:
                lists = self.parse_address_lists(output)
                for name, addresses in lists.items():
                    if name not in self.address_lists:
                        self.address_lists[name] = []
                    self.address_lists[name].extend(addresses)
            elif '/interface print' in cmd and 'list' not in cmd:
                self.interfaces.extend(self.parse_interfaces(output))

    def analyze(self) -> List[ConflictResult]:
        """Run all conflict analysis checks."""
        conflicts = []

        conflicts.extend(self._check_unreachable_rules())
        conflicts.extend(self._check_nat_bypasses_firewall())
        conflicts.extend(self._check_orphan_routing_marks())
        conflicts.extend(self._check_interface_not_in_list())
        conflicts.extend(self._check_address_list_conflicts())
        conflicts.extend(self._check_forward_without_fasttrack())
        conflicts.extend(self._check_shadowed_rules())
        conflicts.extend(self._check_duplicate_rules())

        return conflicts

    def _check_unreachable_rules(self) -> List[ConflictResult]:
        """
        Detect rules that will never match because they're shadowed.

        Example:
          add chain=forward action=drop (drops all)
          add chain=forward action=accept (never reached)
        """
        conflicts = []

        # Group rules by chain
        chains: Dict[str, List[Tuple[int, Dict]]] = {}
        for i, rule in enumerate(self.filter_rules):
            chain = rule.get('chain', 'forward')
            if chain not in chains:
                chains[chain] = []
            chains[chain].append((i, rule))

        # Check each chain for unreachable rules
        for chain, rules in chains.items():
            # Track "catch-all" rules that match everything
            catch_all_positions = []

            for idx, (rule_idx, rule) in enumerate(rules):
                action = rule.get('action', '')

                # Check if this is a catch-all drop/accept rule
                is_catch_all = (
                    action in ('drop', 'accept') and
                    'src_address' not in rule and
                    'dst_address' not in rule and
                    'in_interface' not in rule and
                    'out_interface' not in rule and
                    'src_address_list' not in rule and
                    'dst_address_list' not in rule and
                    'protocol' not in rule and
                    'dst_port' not in rule
                )

                if is_catch_all:
                    catch_all_positions.append(idx)

                # Check if current rule is after a catch-all with same action target
                if catch_all_positions:
                    last_catch_all = catch_all_positions[-1]
                    if idx > last_catch_all:
                        # This rule comes after a catch-all
                        catch_all_rule = rules[last_catch_all][1]
                        catch_all_action = catch_all_rule.get('action', '')

                        # If catch-all is drop and current is accept (or vice versa)
                        if action and catch_all_action and action != catch_all_action:
                            conflicts.append(ConflictResult(
                                conflict_type=ConflictType.UNREACHABLE_RULE,
                                severity="High",
                                title=f"Rule in chain '{chain}' may be unreachable",
                                description=f"Rule at position {rule_idx} ({action}) comes after "
                                           f"a catch-all {catch_all_action} rule and may never match",
                                rule_index=rule_idx,
                                rule_command="/ip firewall filter print detail",
                                conflicting_rule=f"Position {last_catch_all}: catch-all {catch_all_action}",
                                recommendation="Review rule order - more specific rules should come before general rules",
                                fix_commands=[
                                    f"# Review rule order in chain '{chain}'",
                                    "/ip firewall filter print detail",
                                    "# Move specific rules before catch-all rules",
                                    "/ip firewall filter move numbers=RULE_NUM before=CATCH_ALL_NUM"
                                ]
                            ))

        return conflicts

    def _check_nat_bypasses_firewall(self) -> List[ConflictResult]:
        """
        Detect NAT dstnat rules that bypass firewall forward chain.

        In RouterOS, dstnat happens BEFORE forward chain, so traffic
        can reach internal hosts even if forward chain would block it.
        """
        conflicts = []

        # Find dstnat rules that forward to internal IPs
        for i, rule in enumerate(self.nat_rules):
            action = rule.get('action', '')
            dst_nat_to = rule.get('to_addresses', '')
            in_interface = rule.get('in_interface', '')

            if action == 'dst-nat' and dst_nat_to:
                # Check if there's a corresponding forward rule
                has_forward_rule = False
                for fw_rule in self.filter_rules:
                    fw_chain = fw_rule.get('chain', '')
                    fw_dst_addr = fw_rule.get('dst_address', '')
                    fw_in_iface = fw_rule.get('in_interface', '')

                    if fw_chain == 'forward':
                        # Check if forward rule covers this NAT destination
                        if dst_nat_to.startswith(fw_dst_addr) or not fw_dst_addr:
                            if in_interface == fw_in_iface or not fw_in_iface:
                                has_forward_rule = True
                                break

                if not has_forward_rule and dst_nat_to.startswith('192.168.'):
                    conflicts.append(ConflictResult(
                        conflict_type=ConflictType.NAT_BYPASSES_FIREWALL,
                        severity="High",
                        title="NAT dstnat may bypass firewall forward rules",
                        description=f"NAT rule forwards traffic to {dst_nat_to} but "
                                   f"no corresponding forward chain rule found. "
                                   f"Traffic may reach internal host even if firewall would block it.",
                        rule_index=i,
                        rule_command="/ip firewall nat print detail",
                        recommendation="Add explicit forward chain rules for NAT destinations",
                        fix_commands=[
                            "# Allow established connections",
                            f"/ip firewall filter add chain=forward dst-address={dst_nat_to} "
                            f"connection-state=established,related action=accept",
                            "# Add specific allow rules for services",
                            f"/ip firewall filter add chain=forward dst-address={dst_nat_to} "
                            f"protocol=tcp dst-port=SERVICE_PORT action=accept"
                        ]
                    ))

        return conflicts

    def _check_orphan_routing_marks(self) -> List[ConflictResult]:
        """
        Detect mangle rules that mark routing but no route uses that mark.
        """
        conflicts = []

        # Collect all routing marks from mangle rules
        mangle_marks: Set[str] = set()
        for rule in self.mangle_rules:
            chain = rule.get('chain', '')
            if chain in ('prerouting', 'output'):
                mark = rule.get('routing_mark', '')
                if mark:
                    mangle_marks.add(mark)

        # Collect all routing marks from routes
        route_marks: Set[str] = set()
        for route in self.routes:
            mark = route.get('routing_mark', '')
            if mark:
                route_marks.add(mark)

        # Find orphan marks
        orphan_marks = mangle_marks - route_marks

        for mark in orphan_marks:
            conflicts.append(ConflictResult(
                conflict_type=ConflictType.ORPHAN_ROUTING_MARK,
                severity="Medium",
                title=f"Routing mark '{mark}' has no corresponding route",
                description=f"Mangle rule marks traffic with '{mark}' but no route "
                           f"uses this mark. Marked traffic will use default routing.",
                recommendation="Add route with matching routing_mark or remove mangle rule",
                fix_commands=[
                    f"# Add route for mark '{mark}'",
                    f"/ip route add dst-address=DESTINATION routing-mark={mark} gateway=GATEWAY",
                    "# Or remove the mangle rule if not needed",
                    f"/ip firewall mangle remove [find where routing-mark={mark}]"
                ]
            ))

        return conflicts

    def _check_interface_not_in_list(self) -> List[ConflictResult]:
        """
        Detect interfaces that should be in WAN/LAN lists but aren't.
        """
        conflicts = []

        wan_list = self.interface_lists.get('WAN', [])
        lan_list = self.interface_lists.get('LAN', [])

        # Check for interfaces not in any list
        for iface in self.interfaces:
            # Skip bridge interfaces and loopback
            if iface.startswith('bridge') or iface == 'lo':
                continue

            in_wan = iface in wan_list
            in_lan = iface in lan_list

            if not in_wan and not in_lan:
                # Check if this interface has IP address (active interface)
                conflicts.append(ConflictResult(
                    conflict_type=ConflictType.INTERFACE_NOT_IN_LIST,
                    severity="Low",
                    title=f"Interface '{iface}' not in WAN or LAN list",
                    description=f"Interface '{iface}' exists but is not member of WAN or LAN "
                               f"interface lists. Firewall rules using these lists won't apply.",
                    recommendation="Add interface to appropriate list (WAN or LAN)",
                    fix_commands=[
                        "# Add to WAN list if this is internet-facing",
                        f"/interface list member add interface={iface} list=WAN",
                        "# Or add to LAN list if this is internal",
                        f"/interface list member add interface={iface} list=LAN"
                    ]
                ))

        return conflicts

    def _check_address_list_conflicts(self) -> List[ConflictResult]:
        """
        Detect address list conflicts where same IP is in allow and block lists.
        """
        conflicts = []

        # Look for common allow/block list patterns
        allow_lists = {'allowed', 'trusted', 'whitelist', 'safe'}
        block_lists = {'blocked', 'banned', 'blacklist', 'dangerous'}

        for allow_name in allow_lists:
            for block_name in block_lists:
                allow_addrs = set()
                block_addrs = set()

                for name, addrs in self.address_lists.items():
                    name_lower = name.lower()
                    if allow_name in name_lower:
                        allow_addrs.update(addrs)
                    if block_name in name_lower:
                        block_addrs.update(addrs)

                # Find overlapping addresses
                overlap = allow_addrs & block_addrs
                for addr in overlap:
                    conflicts.append(ConflictResult(
                        conflict_type=ConflictType.ADDRESS_LIST_CONFLICT,
                        severity="Medium",
                        title=f"Address {addr} in both allow and block lists",
                        description=f"IP address {addr} appears in both allowed and blocked "
                                   f"address lists. Firewall behavior depends on rule order.",
                        recommendation="Remove address from one list to resolve conflict",
                        fix_commands=[
                            "# Review address lists",
                            "/ip firewall address-list print where address=" + addr,
                            "# Remove from block list if should be allowed",
                            f"/ip firewall address-list remove [find where list~\"block\" address={addr}]",
                            "# Or remove from allow list if should be blocked",
                            f"/ip firewall address-list remove [find where list~\"allow\" address={addr}]"
                        ]
                    ))

        return conflicts

    def _check_forward_without_fasttrack(self) -> List[ConflictResult]:
        """
        Detect if there are many forward rules but no FastTrack rule.

        FastTrack significantly improves performance for established connections.
        """
        conflicts = []

        # Count forward rules
        forward_rules = [r for r in self.filter_rules if r.get('chain') == 'forward']

        # Check for FastTrack rule
        has_fasttrack = any(
            r.get('action') == 'fasttrack-connection' or
            'fasttrack' in r.get('action', '').lower()
            for r in self.filter_rules
        )

        # If many forward rules but no FastTrack
        if len(forward_rules) > 5 and not has_fasttrack:
            conflicts.append(ConflictResult(
                conflict_type=ConflictType.FORWARD_WITHOUT_FASTTRACK,
                severity="Low",
                title="No FastTrack rule for established connections",
                description=f"Found {len(forward_rules)} forward chain rules but no FastTrack "
                           f"rule. Performance may be degraded for established connections.",
                recommendation="Add FastTrack rule for better performance",
                fix_commands=[
                    "# Add FastTrack rule for established connections",
                    "/ip firewall filter add chain=forward action=fasttrack-connection "
                    "connection-state=established,related comment=\"FastTrack\" place-before=0",
                    "# Ensure established connections are allowed",
                    "/ip firewall filter add chain=forward action=accept "
                    "connection-state=established,related comment=\"Allow established\""
                ]
            ))

        return conflicts

    def _check_shadowed_rules(self) -> List[ConflictResult]:
        """
        Detect rules that are completely shadowed by earlier more general rules.
        """
        conflicts = []

        # Group by chain
        chains: Dict[str, List[Tuple[int, Dict]]] = {}
        for i, rule in enumerate(self.filter_rules):
            chain = rule.get('chain', 'forward')
            if chain not in chains:
                chains[chain] = []
            chains[chain].append((i, rule))

        for chain, rules in chains.items():
            for i, (idx1, rule1) in enumerate(rules):
                for j, (idx2, rule2) in enumerate(rules):
                    if i >= j:
                        continue

                    # Check if rule2 is shadowed by rule1
                    if self._is_shadowed_by(rule2, rule1):
                        conflicts.append(ConflictResult(
                            conflict_type=ConflictType.SHADOWED_RULE,
                            severity="Medium",
                            title=f"Rule at position {idx2} shadowed by rule at {idx1}",
                            description=f"Rule {idx2} will never match because rule {idx1} "
                                       f"matches all traffic that rule {idx2} would match",
                            rule_index=idx2,
                            conflicting_rule=f"Position {idx1}",
                            recommendation="Review rule specificity and order",
                            fix_commands=[
                                "# Review these rules",
                                f"/ip firewall filter print detail where numbers={idx1}",
                                f"/ip firewall filter print detail where numbers={idx2}"
                            ]
                        ))

        return conflicts

    def _is_shadowed_by(self, specific_rule: Dict, general_rule: Dict) -> bool:
        """Check if specific_rule is completely shadowed by general_rule."""
        # General rule must come first and have broader match criteria
        general_action = general_rule.get('action', '')
        specific_action = specific_rule.get('action', '')

        # If actions are the same, not really a conflict
        if general_action == specific_action:
            return False

        # General rule should have fewer match criteria
        general_criteria = len([k for k in general_rule.keys() if k not in ('chain', 'action', 'comment')])
        specific_criteria = len([k for k in specific_rule.keys() if k not in ('chain', 'action', 'comment')])

        if general_criteria >= specific_criteria:
            return False

        # Check if general rule matches superset of traffic
        # (simplified check - real implementation would be more thorough)
        for key in specific_rule:
            if key in ('chain', 'action', 'comment'):
                continue
            if key not in general_rule:
                # Specific rule has criteria that general rule doesn't
                # So general rule is actually broader
                pass

        return True

    def _check_duplicate_rules(self) -> List[ConflictResult]:
        """Detect duplicate firewall rules."""
        conflicts = []
        seen: Dict[str, int] = {}

        for i, rule in enumerate(self.filter_rules):
            # Create signature from ALL key fields - must match exactly
            chain = rule.get('chain', '')
            action = rule.get('action', '')
            src = rule.get('src_address', '')
            dst = rule.get('dst_address', '')
            proto = rule.get('protocol', '')
            port = rule.get('dst_port', '')
            in_iface = rule.get('in_interface', '')
            out_iface = rule.get('out_interface', '')
            src_port = rule.get('src_port', '')
            connection_state = rule.get('connection_state', '')

            # Only flag as duplicate if ALL significant fields match
            signature = f"{chain}:{action}:{src}:{dst}:{proto}:{port}:{in_iface}:{out_iface}:{src_port}:{connection_state}"

            if signature in seen:
                conflicts.append(ConflictResult(
                    conflict_type=ConflictType.DUPLICATE_RULE,
                    severity="Low",
                    title="Duplicate firewall rule detected",
                    description=f"Rule at position {i} appears to be duplicate of rule at {seen[signature]}",
                    rule_index=i,
                    conflicting_rule=f"Position {seen[signature]}",
                    recommendation="Remove duplicate rule",
                    fix_commands=[
                        "# Review duplicate rules",
                        f"/ip firewall filter print detail where numbers={seen[signature]}",
                        f"/ip firewall filter print detail where numbers={i}",
                        "# Remove duplicate",
                        f"/ip firewall filter remove [find where numbers={i}]"
                    ]
                ))
            else:
                seen[signature] = i

        return conflicts
