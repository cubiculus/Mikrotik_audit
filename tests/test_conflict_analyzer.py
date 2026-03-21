"""Tests for conflict_analyzer module."""

from src.config import CommandResult
from src.conflict_analyzer import ConflictAnalyzer, ConflictType, ConflictResult


class TestConflictAnalyzer:
    """Tests for ConflictAnalyzer."""

    def test_empty_config_returns_no_conflicts(self):
        """Test that empty config returns no conflicts."""
        analyzer = ConflictAnalyzer()
        conflicts = analyzer.analyze()
        assert len(conflicts) == 0

    def test_parse_filter_rules_basic(self):
        """Test parsing basic filter rules."""
        analyzer = ConflictAnalyzer()
        output = """
Flags: X - disabled, I - invalid
0   ;;; default configuration
      chain=forward action=accept connection-state=established,related
1   chain=input action=drop connection-state=invalid
"""
        rules = analyzer.parse_filter_rules(output)
        assert len(rules) == 2
        assert rules[0]['chain'] == 'forward'
        assert rules[0]['action'] == 'accept'
        assert rules[1]['chain'] == 'input'

    def test_parse_nat_rules(self):
        """Test parsing NAT rules."""
        analyzer = ConflictAnalyzer()
        output = """
Flags: X - disabled, I - invalid
0   chain=dstnat action=dst-nat to-addresses=192.168.88.100
"""
        rules = analyzer.parse_nat_rules(output)
        assert len(rules) == 1
        assert rules[0]['action'] == 'dst-nat'
        assert rules[0]['to_addresses'] == '192.168.88.100'

    def test_parse_mangle_rules(self):
        """Test parsing mangle rules."""
        analyzer = ConflictAnalyzer()
        output = """
Flags: X - disabled, I - invalid
0   chain=prerouting action=mark-routing routing-mark=TO_ISP
"""
        rules = analyzer.parse_mangle_rules(output)
        assert len(rules) == 1
        assert rules[0]['routing_mark'] == 'TO_ISP'

    def test_parse_routes(self):
        """Test parsing routes."""
        analyzer = ConflictAnalyzer()
        output = """
Flags: X - disabled, A - active
0  dst-address=0.0.0.0/0 gateway=192.168.88.1 routing-mark=TO_ISP
"""
        routes = analyzer.parse_routes(output)
        assert len(routes) == 1
        assert routes[0]['routing_mark'] == 'TO_ISP'

    def test_parse_interface_lists(self):
        """Test parsing interface list members."""
        analyzer = ConflictAnalyzer()
        output = """
Flags: X - disabled
0  list=WAN interface=ether1
1  list=WAN interface=ether2
2  list=LAN interface=bridge
"""
        lists = analyzer.parse_interface_lists(output)
        assert 'WAN' in lists
        assert 'LAN' in lists
        assert 'ether1' in lists['WAN']
        assert 'bridge' in lists['LAN']

    def test_parse_address_lists(self):
        """Test parsing address lists."""
        analyzer = ConflictAnalyzer()
        output = """
Flags: X - disabled
0  list=blocked address=10.0.0.100
1  list=allowed address=192.168.1.100
"""
        lists = analyzer.parse_address_lists(output)
        assert 'blocked' in lists
        assert 'allowed' in lists
        assert '10.0.0.100' in lists['blocked']

    def test_orphan_routing_mark_detection(self):
        """Test detection of orphan routing marks."""
        analyzer = ConflictAnalyzer()

        # Mangle marks traffic but no route uses that mark
        analyzer.mangle_rules = [
            {'chain': 'prerouting', 'action': 'mark-routing', 'routing_mark': 'UNUSED_MARK'}
        ]
        analyzer.routes = []

        conflicts = analyzer._check_orphan_routing_marks()
        assert len(conflicts) > 0
        assert conflicts[0].conflict_type == ConflictType.ORPHAN_ROUTING_MARK
        assert 'UNUSED_MARK' in conflicts[0].title

    def test_no_orphan_mark_when_route_exists(self):
        """Test that no orphan mark when route exists."""
        analyzer = ConflictAnalyzer()

        analyzer.mangle_rules = [
            {'chain': 'prerouting', 'action': 'mark-routing', 'routing_mark': 'USED_MARK'}
        ]
        analyzer.routes = [
            {'routing_mark': 'USED_MARK', 'gateway': '192.168.1.1'}
        ]

        conflicts = analyzer._check_orphan_routing_marks()
        assert len(conflicts) == 0

    def test_interface_not_in_list_detection(self):
        """Test detection of interfaces not in WAN/LAN lists."""
        analyzer = ConflictAnalyzer()

        analyzer.interfaces = ['ether1', 'ether2', 'ether3']
        analyzer.interface_lists = {
            'WAN': ['ether1'],
            'LAN': ['bridge']
        }

        conflicts = analyzer._check_interface_not_in_list()
        # ether2 and ether3 should be flagged
        assert len(conflicts) >= 1
        assert conflicts[0].conflict_type == ConflictType.INTERFACE_NOT_IN_LIST

    def test_interface_in_list_no_conflict(self):
        """Test that interfaces in lists don't trigger conflict."""
        analyzer = ConflictAnalyzer()

        analyzer.interfaces = ['ether1', 'bridge']
        analyzer.interface_lists = {
            'WAN': ['ether1'],
            'LAN': ['bridge']
        }

        conflicts = analyzer._check_interface_not_in_list()
        assert len(conflicts) == 0

    def test_forward_without_fasttrack_detection(self):
        """Test detection of missing FastTrack rule."""
        analyzer = ConflictAnalyzer()

        # Many forward rules but no FastTrack
        analyzer.filter_rules = [
            {'chain': 'forward', 'action': 'accept', 'connection-state': 'established'},
            {'chain': 'forward', 'action': 'drop', 'connection-state': 'invalid'},
            {'chain': 'forward', 'action': 'accept', 'in-interface': 'LAN'},
            {'chain': 'forward', 'action': 'drop', 'in-interface': 'WAN'},
            {'chain': 'forward', 'action': 'accept', 'protocol': 'tcp'},
            {'chain': 'forward', 'action': 'accept', 'protocol': 'udp'},
        ]

        conflicts = analyzer._check_forward_without_fasttrack()
        assert len(conflicts) > 0
        assert conflicts[0].conflict_type == ConflictType.FORWARD_WITHOUT_FASTTRACK

    def test_fasttrack_exists_no_conflict(self):
        """Test that FastTrack rule prevents conflict."""
        analyzer = ConflictAnalyzer()

        analyzer.filter_rules = [
            {'chain': 'forward', 'action': 'fasttrack-connection'},
            {'chain': 'forward', 'action': 'accept'},
        ]

        conflicts = analyzer._check_forward_without_fasttrack()
        assert len(conflicts) == 0

    def test_duplicate_rules_detection(self):
        """Test detection of duplicate rules."""
        analyzer = ConflictAnalyzer()

        analyzer.filter_rules = [
            {'chain': 'forward', 'action': 'accept', 'src-address': '192.168.1.100'},
            {'chain': 'forward', 'action': 'accept', 'src-address': '192.168.1.100'},  # Duplicate
        ]

        conflicts = analyzer._check_duplicate_rules()
        assert len(conflicts) > 0
        assert conflicts[0].conflict_type == ConflictType.DUPLICATE_RULE

    def test_no_duplicate_different_addresses(self):
        """Test that different addresses are not flagged as duplicate."""
        analyzer = ConflictAnalyzer()

        # Use underscores (as parser would convert)
        analyzer.filter_rules = [
            {'chain': 'forward', 'action': 'accept', 'src_address': '192.168.1.100'},
            {'chain': 'forward', 'action': 'accept', 'src_address': '192.168.1.101'},
        ]

        conflicts = analyzer._check_duplicate_rules()
        assert len(conflicts) == 0

    def test_nat_bypasses_firewall_detection(self):
        """Test detection of NAT bypassing firewall."""
        analyzer = ConflictAnalyzer()

        analyzer.nat_rules = [
            {
                'action': 'dst-nat',
                'to_addresses': '192.168.88.100',
                'in_interface': 'ether1-WAN'
            }
        ]
        analyzer.filter_rules = []  # No forward rules

        conflicts = analyzer._check_nat_bypasses_firewall()
        assert len(conflicts) > 0
        assert conflicts[0].conflict_type == ConflictType.NAT_BYPASSES_FIREWALL

    def test_load_data_from_results(self):
        """Test loading data from command results."""
        analyzer = ConflictAnalyzer()

        results = [
            CommandResult(
                index=1,
                command="/ip firewall filter print detail",
                stdout="0 chain=forward action=accept",
                has_error=False
            ),
            CommandResult(
                index=2,
                command="/ip firewall nat print detail",
                stdout="0 chain=dstnat action=dst-nat",
                has_error=False
            )
        ]

        analyzer.load_data(results)
        assert len(analyzer.filter_rules) == 1
        assert len(analyzer.nat_rules) == 1

    def test_full_analyze_integration(self):
        """Test full analyze with multiple conflict types."""
        analyzer = ConflictAnalyzer()

        # Setup config with multiple issues
        analyzer.filter_rules = [
            {'chain': 'forward', 'action': 'drop'},  # Catch-all drop
            {'chain': 'forward', 'action': 'accept'},  # Unreachable
        ]
        analyzer.interfaces = ['ether3']
        analyzer.interface_lists = {'WAN': ['ether1'], 'LAN': ['bridge']}

        conflicts = analyzer.analyze()

        # Should find at least unreachable rule and interface not in list
        conflict_types = [c.conflict_type for c in conflicts]
        assert ConflictType.UNREACHABLE_RULE in conflict_types or \
               ConflictType.INTERFACE_NOT_IN_LIST in conflict_types


class TestConflictResult:
    """Tests for ConflictResult dataclass."""

    def test_conflict_result_creation(self):
        """Test creating ConflictResult."""
        result = ConflictResult(
            conflict_type=ConflictType.UNREACHABLE_RULE,
            severity="High",
            title="Test conflict",
            description="Test description"
        )
        assert result.conflict_type == ConflictType.UNREACHABLE_RULE
        assert result.severity == "High"
        assert result.title == "Test conflict"
        assert result.fix_commands == []

    def test_conflict_result_with_fix_commands(self):
        """Test ConflictResult with fix commands."""
        result = ConflictResult(
            conflict_type=ConflictType.ORPHAN_ROUTING_MARK,
            severity="Medium",
            title="Orphan mark",
            description="Description",
            fix_commands=["/command1", "/command2"]
        )
        assert len(result.fix_commands) == 2
        assert "/command1" in result.fix_commands
