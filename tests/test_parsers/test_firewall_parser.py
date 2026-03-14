"""Tests for firewall parser."""

from src.parsers.firewall_parser import parse_nat_rules, parse_filter_rules, parse_mangle_rules
from src.config import CommandResult


class TestNATParser:
    """Tests for NAT rules parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        rules = parse_nat_rules([])
        assert rules == []

    def test_parse_nat_with_comments(self):
        """Test parsing NAT rules with comments."""
        output = """Flags: X - DISABLED
 0  ;;; Masquerade for LAN
      chain=srcnat action=masquerade out-interface=ether1-WAN src-address=192.168.100.0/24

 1  ;;; Port Forward - Web Server
      chain=dstnat action=dst-nat to-addresses=192.168.100.100 to-ports=80 protocol=tcp
      dst-port=8080 in-interface=ether1-WAN
"""
        results = [CommandResult(index=0, command="/ip firewall nat print detail", stdout=output)]
        rules = parse_nat_rules(results)

        assert len(rules) >= 1
        if len(rules) > 0:
            assert rules[0].chain == "srcnat"
            assert rules[0].action == "masquerade"

    def test_parse_nat_without_comments(self):
        """Test parsing NAT rules without comments."""
        output = """Flags: X - DISABLED
 0  chain=srcnat action=masquerade out-interface=ether1
 1  chain=dstnat action=dst-nat to-addresses=10.0.0.1 protocol=tcp dst-port=443
"""
        results = [CommandResult(index=0, command="/ip firewall nat print detail", stdout=output)]
        rules = parse_nat_rules(results)

        assert len(rules) == 2
        assert rules[0].comment == ""
        assert rules[1].action == "dst-nat"

    def test_parse_disabled_nat_rule(self):
        """Test parsing disabled NAT rule."""
        output = """Flags: X - DISABLED
 0 X chain=srcnat action=masquerade disabled=yes
"""
        results = [CommandResult(index=0, command="/ip firewall nat print detail", stdout=output)]
        rules = parse_nat_rules(results)

        assert len(rules) == 1
        assert rules[0].disabled is True


class TestFilterParser:
    """Tests for Filter rules parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        rules = parse_filter_rules([])
        assert rules == []

    def test_parse_filter_with_comments(self):
        """Test parsing Filter rules with comments."""
        output = """Flags: X - DISABLED
 0  ;;; FastTrack - MUST BE FIRST
      chain=forward action=fasttrack-connection connection-state=established,related

 1  ;;; Accept Established Connections
      chain=forward action=accept connection-state=established,related

 2  ;;; Drop Invalid
      chain=forward action=drop connection-state=invalid
"""
        results = [CommandResult(index=0, command="/ip firewall filter print detail", stdout=output)]
        rules = parse_filter_rules(results)

        assert len(rules) == 3
        assert rules[0].comment == "FastTrack - MUST BE FIRST"
        assert rules[0].action == "fasttrack-connection"
        assert rules[1].comment == "Accept Established Connections"
        assert rules[2].comment == "Drop Invalid"

    def test_parse_filter_complex_rule(self):
        """Test parsing complex Filter rule."""
        output = """Flags: X - DISABLED
 0  chain=input action=accept protocol=tcp dst-port=22 in-interface=ether1
      src-address=192.168.100.0/24 log=yes log-prefix="SSH Access"
"""
        results = [CommandResult(index=0, command="/ip firewall filter print detail", stdout=output)]
        rules = parse_filter_rules(results)

        assert len(rules) == 1
        assert rules[0].chain == "input"
        assert rules[0].action == "accept"
        assert rules[0].protocol == "tcp"
        assert rules[0].dst_port == "22"
        assert rules[0].src_address == "192.168.100.0/24"
        assert rules[0].log == "yes"
        assert rules[0].log_prefix == "SSH Access"

    def test_parse_filter_connection_states(self):
        """Test parsing Filter rules with connection states."""
        output = """Flags: X - DISABLED
 0  chain=forward action=accept connection-state=established,related
 1  chain=forward action=drop connection-state=invalid
 2  chain=input action=accept connection-nat-state=dstnat
"""
        results = [CommandResult(index=0, command="/ip firewall filter print detail", stdout=output)]
        rules = parse_filter_rules(results)

        assert rules[0].connection_state == "established,related"
        assert rules[1].connection_state == "invalid"
        assert rules[2].connection_nat_state == "dstnat"


class TestMangleParser:
    """Tests for Mangle rules parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        rules = parse_mangle_rules([])
        assert rules == []

    def test_parse_mangle_with_comments(self):
        """Test parsing Mangle rules with comments."""
        output = """Flags: X - DISABLED
 0  ;;; Mark VPN traffic
      chain=prerouting action=mark-connection new-connection-mark=vpn_conn
      protocol=tcp dst-port=1194

 1  ;;; Mark packets for VPN
      chain=prerouting action=mark-packet new-packet-mark=vpn_pkt
      connection-mark=vpn_conn passthrough=yes
"""
        results = [CommandResult(index=0, command="/ip firewall mangle print detail", stdout=output)]
        rules = parse_mangle_rules(results)

        assert len(rules) == 2
        assert rules[0].comment == "Mark VPN traffic"
        assert rules[0].action == "mark-connection"
        assert rules[0].new_connection_mark == "vpn_conn"

        assert rules[1].comment == "Mark packets for VPN"
        assert rules[1].action == "mark-packet"
        assert rules[1].passthrough == "yes"

    def test_parse_mangle_routing_mark(self):
        """Test parsing Mangle rules with routing mark."""
        output = """Flags: X - DISABLED
 0  chain=prerouting action=mark-routing new-routing-mark=to_isp2
      dst-address-list=ISP2_Routes
"""
        results = [CommandResult(index=0, command="/ip firewall mangle print detail", stdout=output)]
        rules = parse_mangle_rules(results)

        assert len(rules) == 1
        assert rules[0].new_routing_mark == "to_isp2"
        assert rules[0].dst_address_list == "ISP2_Routes"

    def test_parse_mangle_with_passthrough(self):
        """Test parsing Mangle rules with passthrough."""
        output = """Flags: X - DISABLED
 0  chain=prerouting action=mark-packet new-packet-mark=web_pkt passthrough=yes
      dst-port=80,443 protocol=tcp
"""
        results = [CommandResult(index=0, command="/ip firewall mangle print detail", stdout=output)]
        rules = parse_mangle_rules(results)

        assert len(rules) == 1
        assert rules[0].passthrough == "yes"
        assert rules[0].dst_port == "80,443"


class TestFirewallCommentParsing:
    """Tests specifically for comment parsing in firewall rules."""

    def test_comment_on_separate_line(self):
        """Test comment on line before rule."""
        output = """ 0  ;;; This is a comment
      chain=input action=accept
"""
        results = [CommandResult(index=0, command="/ip firewall filter print detail", stdout=output)]
        rules = parse_filter_rules(results)

        assert len(rules) == 1
        assert rules[0].comment == "This is a comment"

    def test_comment_with_special_chars(self):
        """Test comment with special characters."""
        output = """ 0  ;;; Comment with "quotes" and special chars: <>&
      chain=input action=accept
"""
        results = [CommandResult(index=0, command="/ip firewall filter print detail", stdout=output)]
        rules = parse_filter_rules(results)

        assert len(rules) == 1
        assert rules[0].comment == 'Comment with "quotes" and special chars: <>&'

    def test_multiple_comments_in_output(self):
        """Test multiple comments in output."""
        output = """ 0  ;;; First rule comment
      chain=input action=accept dst-port=22
 1  ;;; Second rule comment
      chain=input action=accept dst-port=80
 2  ;;; Third rule comment
      chain=input action=drop
"""
        results = [CommandResult(index=0, command="/ip firewall filter print detail", stdout=output)]
        rules = parse_filter_rules(results)

        assert len(rules) == 3
        assert rules[0].comment == "First rule comment"
        assert rules[1].comment == "Second rule comment"
        assert rules[2].comment == "Third rule comment"

    def test_rule_without_comment_when_comments_exist(self):
        """Test rule without comment when other rules have comments."""
        output = """ 0  ;;; Has comment
      chain=input action=accept dst-port=22
 1  chain=input action=drop dst-port=23
"""
        results = [CommandResult(index=0, command="/ip firewall filter print detail", stdout=output)]
        rules = parse_filter_rules(results)

        assert len(rules) == 2
        assert rules[0].comment == "Has comment"
        assert rules[1].comment == ""
