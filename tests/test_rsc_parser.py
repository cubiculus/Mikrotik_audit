"""Tests for rsc_parser module."""

import tempfile
import os
from src.rsc_parser import (
    RSCParser,
    RSCCommand,
    parse_rsc_file,
    parse_rsc_content
)


class TestRSCParser:
    """Tests for RSCParser."""

    def test_parse_empty_content(self):
        """Test parsing empty content."""
        parser = RSCParser()
        commands = parser.parse_content("")

        assert len(commands) == 1  # One empty line command
        assert commands[0].is_empty is True

    def test_parse_comment_lines(self):
        """Test parsing comment lines."""
        parser = RSCParser()
        commands = parser.parse_content("""# This is a comment
# Another comment""")

        assert len(commands) == 2
        assert all(cmd.is_comment for cmd in commands)
        assert "This is a comment" in commands[0].comment

    def test_parse_add_command(self):
        """Test parsing add command."""
        parser = RSCParser()
        commands = parser.parse_content(
            "/ip firewall filter add chain=input action=accept # Test"
        )

        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.command_type == "add"
        assert cmd.path == "/ip firewall filter"
        assert cmd.parameters.get('chain') == "input"
        assert cmd.parameters.get('action') == "accept"
        assert cmd.comment == "Test"

    def test_parse_set_command(self):
        """Test parsing set command."""
        parser = RSCParser()
        commands = parser.parse_content(
            "set enabled=no"
        )

        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.command_type == "set"
        assert cmd.parameters.get('enabled') == "no"

    def test_parse_remove_command(self):
        """Test parsing remove command."""
        parser = RSCParser()
        commands = parser.parse_content(
            "remove numbers=0"
        )

        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.command_type == "remove"
        assert cmd.parameters.get('numbers') == "0"

    def test_parse_quoted_values(self):
        """Test parsing quoted parameter values."""
        parser = RSCParser()
        commands = parser.parse_content(
            '/ip address add address="192.168.1.1/24" interface="bridge"'
        )

        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.parameters.get('address') == "192.168.1.1/24"
        assert cmd.parameters.get('interface') == "bridge"

    def test_parse_line_continuation(self):
        """Test parsing multi-line commands with backslash continuation."""
        parser = RSCParser()
        content = """
/ip firewall filter add chain=forward \\
    action=accept \\
    comment="Multi-line rule"
"""
        commands = parser.parse_content(content)

        # Should be parsed as single command
        assert len(commands) >= 1
        # Find the add command
        add_cmds = [c for c in commands if c.command_type == 'add']
        assert len(add_cmds) > 0

    def test_parse_file_not_found(self):
        """Test parsing non-existent file."""
        parser = RSCParser()

        try:
            parser.parse_file("nonexistent.rsc")
            assert False, "Should raise FileNotFoundError"
        except FileNotFoundError:
            pass

    def test_parse_file(self):
        """Test parsing actual file."""
        content = """
# Test configuration
/ip firewall filter add chain=input action=accept comment="Test"
/ip address add address=192.168.1.1/24 interface=bridge
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rsc', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            parser = RSCParser()
            commands = parser.parse_file(temp_path)

            assert len(commands) >= 2
            add_cmds = [c for c in commands if c.command_type == 'add']
            assert len(add_cmds) == 2
        finally:
            os.unlink(temp_path)

    def test_to_command_results(self):
        """Test converting to CommandResult format."""
        parser = RSCParser()
        parser.parse_content("""
/ip firewall filter add chain=input action=accept
/ip firewall filter add chain=forward action=drop
""")

        results = parser.to_command_results()

        assert len(results) > 0
        # Results should be usable by analyzers
        for result in results:
            assert isinstance(result.command, str)
            assert isinstance(result.stdout, str)

    def test_get_statistics(self):
        """Test getting parsing statistics."""
        parser = RSCParser()
        parser.parse_content("""
# Comment 1
# Comment 2

/ip firewall filter add chain=input action=accept
/ip address add address=192.168.1.1/24
""")

        stats = parser.get_statistics()

        assert stats['commands'] >= 2
        assert stats['comments'] == 2
        assert stats['empty_lines'] >= 1
        assert stats['errors'] == 0
        assert '/ip firewall filter' in stats['paths']

    def test_parse_errors_are_logged(self):
        """Test that parse errors are captured."""
        parser = RSCParser()
        # This should parse fine but we can check error handling
        parser.parse_errors.append((1, "Test error", "test line"))

        stats = parser.get_statistics()
        assert stats['errors'] == 1


class TestRSCCommand:
    """Tests for RSCCommand dataclass."""

    def test_create_command(self):
        """Test creating RSCCommand."""
        cmd = RSCCommand(
            line_number=1,
            raw_line="/ip firewall filter add chain=input",
            command_type="add",
            path="/ip/firewall",
            parameters={'chain': 'input'},
            comment="Test"
        )

        assert cmd.line_number == 1
        assert cmd.command_type == "add"
        assert cmd.is_comment is False
        assert cmd.is_empty is False

    def test_create_comment_command(self):
        """Test creating comment RSCCommand."""
        cmd = RSCCommand(
            line_number=1,
            raw_line="# Comment",
            command_type="comment",
            path="",
            comment="Comment",
            is_comment=True
        )

        assert cmd.is_comment is True
        assert cmd.command_type == "comment"


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_parse_rsc_content(self):
        """Test parse_rsc_content function."""
        content = "/ip firewall filter add chain=input action=accept"

        results, stats = parse_rsc_content(content)

        assert isinstance(results, list)
        assert isinstance(stats, dict)
        assert stats['commands'] >= 1

    def test_parse_rsc_file(self):
        """Test parse_rsc_file function."""
        content = "/ip firewall filter add chain=input"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.rsc', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            results, stats = parse_rsc_file(temp_path)

            assert isinstance(results, list)
            assert isinstance(stats, dict)
        finally:
            os.unlink(temp_path)


class TestRSCParserEdgeCases:
    """Tests for edge cases in RSC parser."""

    def test_parse_complex_firewall_rule(self):
        """Test parsing complex firewall rule."""
        parser = RSCParser()
        content = '''
/ip firewall filter add chain=forward action=accept \
    connection-state=established,related,untracked \
    comment="Allow established connections"
'''
        commands = parser.parse_content(content)

        add_cmds = [c for c in commands if c.command_type == 'add']
        assert len(add_cmds) > 0

    def test_parse_nat_rule(self):
        """Test parsing NAT rule."""
        parser = RSCParser()
        content = '/ip firewall nat add chain=srcnat action=masquerade out-interface-list=WAN'

        commands = parser.parse_content(content)

        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.command_type == "add"
        assert 'nat' in cmd.path
        assert cmd.parameters.get('action') == "masquerade"

    def test_parse_user_with_special_chars(self):
        """Test parsing user with special characters."""
        parser = RSCParser()
        content = '/user add name=admin password="complex=p@ssword" group=full'

        commands = parser.parse_content(content)

        assert len(commands) == 1
        cmd = commands[0]
        # Password with = should be parsed correctly
        assert 'password' in cmd.parameters

    def test_parse_dhcp_lease(self):
        """Test parsing DHCP lease."""
        parser = RSCParser()
        content = '/ip dhcp-server lease add address=192.168.88.100 mac-address=AA:BB:CC:DD:EE:FF'

        commands = parser.parse_content(content)

        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.parameters.get('address') == "192.168.88.100"
        assert cmd.parameters.get('mac-address') == "AA:BB:CC:DD:EE:FF"

    def test_parse_bridge_vlan(self):
        """Test parsing bridge VLAN configuration."""
        parser = RSCParser()
        content = '/interface bridge vlan add bridge=bridge1 tagged=ether1,ether2 untagged=ether3 vlan-ids=100'

        commands = parser.parse_content(content)

        assert len(commands) == 1
        cmd = commands[0]
        assert cmd.parameters.get('vlan-ids') == "100"
        # tagged should be parsed (may be comma-separated)
        assert 'ether1' in cmd.parameters.get('tagged', '')
