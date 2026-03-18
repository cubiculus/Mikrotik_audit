"""Tests for routing parser."""

from src.parsers.routing_parser import (
    parse_routes,
    parse_routing_rules,
    parse_dns_config,
    _parse_route_line_cached,
    _safe_bool,
    _safe_int,
    _build_other_fields
)
from src.config import CommandResult
from src.models import DNSInfo


class TestRouteParserHelpers:
    """Tests for helper functions in routing parser."""

    def test_safe_bool_true_values(self):
        """Test _safe_bool with true values."""
        assert _safe_bool("yes") is True
        assert _safe_bool("true") is True
        assert _safe_bool("YES") is True
        assert _safe_bool("TRUE") is True

    def test_safe_bool_false_values(self):
        """Test _safe_bool with false values."""
        assert _safe_bool("no") is False
        assert _safe_bool("false") is False
        assert _safe_bool("anything") is False
        assert _safe_bool("") is False

    def test_safe_int_valid(self):
        """Test _safe_int with valid values."""
        assert _safe_int("100") == 100
        assert _safe_int("0") == 0

    def test_safe_int_invalid(self):
        """Test _safe_int with invalid values."""
        assert _safe_int("abc") == 0
        assert _safe_int("") == 0
        assert _safe_int(None) == 0

    def test_safe_int_default(self):
        """Test _safe_int with custom default."""
        assert _safe_int("abc", default=42) == 42

    def test_build_other_fields(self):
        """Test building other_fields dict."""
        rule_dict = {
            "action": "lookup",
            "src-address": "192.168.1.0/24",
            "unknown-field": "value",
            "another-field": "data"
        }
        known_fields = {"action", "src-address"}
        other_fields = _build_other_fields(rule_dict, known_fields)

        assert "action" not in other_fields
        assert "src-address" not in other_fields
        assert other_fields["unknown-field"] == "value"
        assert other_fields["another-field"] == "data"

    def test_parse_route_line_cached_basic(self):
        """Test parsing basic route line."""
        line = "dst-address=192.168.1.0/24 gateway=10.0.0.1"
        result = _parse_route_line_cached(line)
        assert result["dst-address"] == "192.168.1.0/24"
        assert result["gateway"] == "10.0.0.1"

    def test_parse_route_line_cached_with_status_prefix(self):
        """Test parsing route line with RouterOS v7 status prefix."""
        line = "DAc   dst-address=172.18.0.0/24 gateway=internal"
        result = _parse_route_line_cached(line)
        assert result["dst-address"] == "172.18.0.0/24"
        assert result["gateway"] == "internal"

    def test_parse_route_line_cached_with_routing_mark(self):
        """Test parsing route with routing mark."""
        line = "  dst-address=0.0.0.0/0 gateway=10.0.0.1 routing-mark=to-internet"
        result = _parse_route_line_cached(line)
        assert result["routing-mark"] == "to-internet"

    def test_parse_route_line_cached_with_disabled(self):
        """Test parsing disabled route."""
        line = "DAc   dst-address=10.0.0.0/8 gateway=192.168.1.1 disabled=yes"
        result = _parse_route_line_cached(line)
        assert result["disabled"] == "yes"

    def test_parse_route_line_cached_empty(self):
        """Test parsing empty line."""
        result = _parse_route_line_cached("")
        assert result == {}

    def test_parse_route_line_cached_caching(self):
        """Test that route parsing is cached."""
        line = "dst-address=192.168.1.0/24 gateway=10.0.0.1"
        result1 = _parse_route_line_cached(line)
        result2 = _parse_route_line_cached(line)
        assert result1 == result2


class TestRouteParser:
    """Tests for route parsing function."""

    def test_parse_routes_empty_results(self):
        """Test parsing empty route results."""
        routes = parse_routes([])
        assert routes == []

    def test_parse_routes_no_matching_command(self):
        """Test parsing results without route command."""
        results = [
            CommandResult(
                index=0,
                command="/ip address print",
                stdout="dst-address=192.168.1.0/24"
            )
        ]
        routes = parse_routes(results)
        assert routes == []

    def test_parse_routes_basic(self):
        """Test parsing basic routes."""
        output = """Flags: D - DYNAMIC, A - ACTIVE
 0  DA  dst-address=192.168.1.0/24 gateway=10.0.0.1 distance=1
 1  DA  dst-address=0.0.0.0/0 gateway=10.0.0.254 distance=1
"""
        results = [
            CommandResult(
                index=0,
                command="/ip route print",
                stdout=output
            )
        ]
        routes = parse_routes(results)

        assert len(routes) == 2
        assert routes[0].dst_address == "192.168.1.0/24"
        assert routes[0].gateway == "10.0.0.1"
        assert routes[1].dst_address == "0.0.0.0/0"

    def test_parse_routes_with_routing_mark(self):
        """Test parsing routes with routing mark."""
        output = """Flags: D - DYNAMIC
 0  D  dst-address=10.0.0.0/8 gateway=172.16.0.1 routing-mark=corporate
"""
        results = [
            CommandResult(
                index=0,
                command="/ip route print",
                stdout=output
            )
        ]
        routes = parse_routes(results)

        assert len(routes) == 1
        assert routes[0].routing_mark == "corporate"

    def test_parse_routes_disabled(self):
        """Test parsing disabled routes."""
        output = """Flags: D - DYNAMIC
 0  D  dst-address=192.168.100.0/24 gateway=10.0.0.1 disabled=yes
"""
        results = [
            CommandResult(
                index=0,
                command="/ip route print",
                stdout=output
            )
        ]
        routes = parse_routes(results)

        assert len(routes) == 1
        assert routes[0].disabled is True

    def test_parse_routes_with_comment(self):
        """Test parsing routes with comments."""
        output = """Flags: D - DYNAMIC
 0  D  dst-address=192.168.1.0/24 gateway=10.0.0.1 comment="To office"
"""
        results = [
            CommandResult(
                index=0,
                command="/ip route print",
                stdout=output
            )
        ]
        routes = parse_routes(results)

        assert len(routes) == 1
        assert routes[0].comment == '"To office"'

    def test_parse_routes_v7_format(self):
        """Test parsing routes in RouterOS v7 format."""
        output = """Flags: D - DYNAMIC; A - ACTIVE
 0  DAc  dst-address=172.18.0.0/24 routing-table=main gateway=internal distance=1
 1  DAo  dst-address=0.0.0.0/0 routing-table=main gateway=isp1 distance=1
"""
        results = [
            CommandResult(
                index=0,
                command="/ip route print",
                stdout=output
            )
        ]
        routes = parse_routes(results)

        assert len(routes) == 2
        assert routes[0].dst_address == "172.18.0.0/24"
        assert routes[0].gateway == "internal"


class TestRoutingRulesParser:
    """Tests for routing rules parser."""

    def test_parse_routing_rules_empty(self):
        """Test parsing empty routing rules."""
        rules = parse_routing_rules([])
        assert rules == []

    def test_parse_routing_rules_basic(self):
        """Test parsing basic routing rules."""
        output = """Flags: I - INACTIVE
 0   action=lookup src-address=192.168.1.0/24 table=main
 1   action=unreachable dst-address=10.0.0.0/8
"""
        results = [
            CommandResult(
                index=0,
                command="/routing rule print",
                stdout=output
            )
        ]
        rules = parse_routing_rules(results)

        assert len(rules) == 2
        assert rules[0]["action"] == "lookup"
        assert rules[1]["action"] == "unreachable"

    def test_parse_routing_rules_complex(self):
        """Test parsing complex routing rules."""
        output = """Flags: I - INACTIVE
 0   action=lookup src-address=192.168.1.0/24 dst-address=10.0.0.0/8 table=corporate
"""
        results = [
            CommandResult(
                index=0,
                command="/routing rule print",
                stdout=output
            )
        ]
        rules = parse_routing_rules(results)

        assert len(rules) == 1
        assert rules[0]["src-address"] == "192.168.1.0/24"
        assert rules[0]["dst-address"] == "10.0.0.0/8"


class TestDNSConfigParser:
    """Tests for DNS config parser."""

    def test_parse_dns_config_empty(self):
        """Test parsing empty DNS config."""
        dns_info = parse_dns_config([])
        assert isinstance(dns_info, DNSInfo)
        assert dns_info.servers == []

    def test_parse_dns_config_basic(self):
        """Test parsing basic DNS config."""
        output = """servers: 8.8.8.8, 8.8.4.4
  allow-remote-requests: yes
  cache-size: 2048
"""
        results = [
            CommandResult(
                index=0,
                command="/ip dns print",
                stdout=output
            )
        ]
        dns_info = parse_dns_config(results)

        assert dns_info.servers == ["8.8.8.8", "8.8.4.4"]
        assert dns_info.allow_remote is True
        assert dns_info.cache_size == 2048

    def test_parse_dns_config_with_doh(self):
        """Test parsing DNS config with DoH."""
        output = """servers: 1.1.1.1
  use-doh: yes
  doh-server: https://cloudflare-dns.com/dns-query
"""
        results = [
            CommandResult(
                index=0,
                command="/ip dns print",
                stdout=output
            )
        ]
        dns_info = parse_dns_config(results)

        assert dns_info.use_doh is True
        assert dns_info.doh_server == "https://cloudflare-dns.com/dns-query"

    def test_parse_dns_config_remote_disabled(self):
        """Test parsing DNS config with remote requests disabled."""
        output = """servers: 192.168.1.1
  allow-remote-requests: no
"""
        results = [
            CommandResult(
                index=0,
                command="/ip dns print",
                stdout=output
            )
        ]
        dns_info = parse_dns_config(results)

        assert dns_info.allow_remote is False
        assert dns_info.servers == ["192.168.1.1"]

    def test_parse_dns_static_entries(self):
        """Test parsing static DNS entries."""
        output = """Flags: D - DYNAMIC
 0   name=example.com address=192.168.1.100
 1   name=internal.local address=10.0.0.50
"""
        results = [
            CommandResult(
                index=0,
                command="/ip dns static print",
                stdout=output
            )
        ]
        dns_info = parse_dns_config(results)

        assert len(dns_info.static_entries) == 2
        assert dns_info.static_entries[0]["name"] == "example.com"
        assert dns_info.static_entries[1]["address"] == "10.0.0.50"

    def test_parse_dns_config_multiple_servers(self):
        """Test parsing DNS config with multiple servers."""
        output = """servers: 8.8.8.8,1.1.1.1,208.67.222.222
"""
        results = [
            CommandResult(
                index=0,
                command="/ip dns print",
                stdout=output
            )
        ]
        dns_info = parse_dns_config(results)

        assert len(dns_info.servers) == 3
        assert "8.8.8.8" in dns_info.servers
        assert "1.1.1.1" in dns_info.servers
        assert "208.67.222.222" in dns_info.servers
