"""Tests for topology parser."""

from src.parsers.topology_parser import (
    parse_bridge_ports,
    parse_wireguard_peers,
    parse_ppp_active,
    parse_arp,
)
from src.config import CommandResult


class TestBridgePortParser:
    """Tests for bridge port parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        ports = parse_bridge_ports([])
        assert ports == []

    def test_parse_bridge_ports(self):
        """Test parsing bridge ports."""
        output = """Flags: X - DISABLED; H - HW-OFFLOAD-CAPABLE
Columns: BRIDGE, PORT, PRIORITY, PATH-COST
 0     bridge=bridge1 port=ether1 priority=128 path-cost=100
      edge=yes p2p=yes learning=yes hw=yes
 1     bridge=bridge1 port=ether2 priority=128 path-cost=100
      edge=no p2p=yes learning=yes hw=no
"""
        results = [CommandResult(index=0, command="/interface bridge port print detail", stdout=output)]
        ports = parse_bridge_ports(results)

        assert len(ports) == 2
        assert ports[0].bridge == "bridge1"
        assert ports[0].port == "ether1"
        assert ports[0].priority == 128
        assert ports[0].path_cost == 100
        assert ports[0].hw is True
        assert ports[0].learning is True


class TestWireGuardPeerParser:
    """Tests for WireGuard peer parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        peers = parse_wireguard_peers([])
        assert peers == []

    def test_parse_wireguard_peers(self):
        """Test parsing WireGuard peers."""
        output = """Flags: X - DISABLED
Columns: INTERFACE, PUBLIC-KEY, ENDPOINT-ADDRESS, ENDPOINT-PORT, ALLOWED-ADDRESS
 0     interface=wg1 public-key="abc123def456..."
      endpoint-address=203.0.113.50 endpoint-port=51820
      allowed-address=192.168.100.0/24
      persistent-keepalive=25s
      last-handshake=5m ago
      tx-bytes=123456 rx-bytes=789012
"""
        results = [CommandResult(index=0, command="/interface wireguard peers print detail", stdout=output)]
        peers = parse_wireguard_peers(results)

        assert len(peers) == 1
        assert peers[0].interface == "wg1"
        assert peers[0].endpoint_address == "203.0.113.50"
        assert peers[0].endpoint_port == 51820
        assert peers[0].allowed_address == "192.168.100.0/24"
        assert peers[0].persistent_keepalive == 25
        assert peers[0].tx_bytes == 123456
        assert peers[0].rx_bytes == 789012


class TestPPPActiveParser:
    """Tests for PPP active parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        connections = parse_ppp_active([])
        assert connections == []

    def test_parse_ppp_active(self):
        """Test parsing PPP active connections."""
        output = """Flags:
Columns: USER, ADDRESS, SERVICE, CALLER-ID, ENCODING, CONNECTED-SINCE
 0     user=admin address=192.168.100.2 service=l2tp
      caller-id=203.0.113.50 encoding=MPPE128
      connected-since=2h30m session-id=0x12345
      uptime=2h30m rate-tx=1000000 rate-rx=2000000
      total-tx=123456789 total-rx=987654321
"""
        results = [CommandResult(index=0, command="/ppp active print detail", stdout=output)]
        connections = parse_ppp_active(results)

        assert len(connections) == 1
        assert connections[0].user == "admin"
        assert connections[0].address == "192.168.100.2"
        assert connections[0].service == "l2tp"
        assert connections[0].caller_id == "203.0.113.50"
        assert connections[0].encoding == "MPPE128"
        assert connections[0].uptime == "2h30m"


class TestARPParser:
    """Tests for ARP parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        entries = parse_arp([])
        assert entries == []

    def test_parse_arp(self):
        """Test parsing ARP table."""
        output = """Flags: D - DYNAMIC; P - PUBLISHED
Columns: ADDRESS, MAC-ADDRESS, INTERFACE, STATUS
 0     address=192.168.100.100 mac-address=AA:BB:CC:DD:EE:01
      interface=bridge status=completed dynamic=yes
 1  P  address=192.168.100.1 mac-address=AA:BB:CC:DD:EE:00
      interface=bridge status=published
"""
        results = [CommandResult(index=0, command="/ip arp print detail", stdout=output)]
        entries = parse_arp(results)

        assert len(entries) == 2
        assert entries[0].address == "192.168.100.100"
        assert entries[0].mac_address == "AA:BB:CC:DD:EE:01"
        assert entries[0].interface == "bridge"
        assert entries[0].status == "completed"
        assert entries[0].dynamic is True

        assert entries[1].published is True
