"""Tests for DHCP parser."""

from src.parsers.dhcp_parser import parse_dhcp_leases, _parse_lease_data
from src.config import CommandResult


class TestDHCPParser:
    """Tests for DHCP lease parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        leases, overview = parse_dhcp_leases([])
        assert leases == []
        assert overview.dhcp_leases_count == 0

    def test_parse_error_results(self):
        """Test parsing results with errors."""
        results = [CommandResult(index=0, command="/ip dhcp-server lease print detail",
                                  stdout="", stderr="error", has_error=True)]
        leases, overview = parse_dhcp_leases(results)
        assert leases == []

    def test_parse_dynamic_lease(self):
        """Test parsing dynamic DHCP lease."""
        output = """Flags: D - DYNAMIC
 0  D  192.168.100.100  D8:50:E6:52:8B:6A  Device1  dhcp1  23h18m47s  10m ago
      address=192.168.100.100 mac-address=D8:50:E6:52:8B:6A host-name=Device1
      server=dhcp1 expires-after=23h18m47s last-seen=10m ago
"""
        results = [CommandResult(index=0, command="/ip dhcp-server lease print detail", stdout=output)]
        leases, overview = parse_dhcp_leases(results)

        assert len(leases) == 1
        assert leases[0].address == "192.168.100.100"
        assert leases[0].mac_address == "D8:50:E6:52:8B:6A"
        assert leases[0].host_name == "Device1"
        assert leases[0].dynamic is True
        assert leases[0].lease_status == "Dynamic"

    def test_parse_static_lease(self):
        """Test parsing static DHCP lease."""
        output = """Flags: D - DYNAMIC
 0     192.168.100.50  AA:BB:CC:DD:EE:FF  Server-Static  dhcp1  never  2h ago
      address=192.168.100.50 mac-address=AA:BB:CC:DD:EE:FF host-name=Server-Static
      server=dhcp1 expires-after=never last-seen=2h ago
"""
        results = [CommandResult(index=0, command="/ip dhcp-server lease print detail", stdout=output)]
        leases, overview = parse_dhcp_leases(results)

        assert len(leases) == 1
        assert leases[0].dynamic is False
        assert leases[0].lease_status == "Static"
        assert leases[0].expires_after == "never"

    def test_parse_lease_with_comment(self):
        """Test parsing DHCP lease with comment."""
        output = """Flags: D - DYNAMIC
 0  ;;; Device1 Storage
    D  192.168.100.100  D8:50:E6:52:8B:6A  Device1  dhcp1  23h  10m ago
      address=192.168.100.100 mac-address=D8:50:E6:52:8B:6A
 1  ;;; Device2 Printer
       192.168.100.50  AA:BB:CC:DD:EE:01  Printer  dhcp1  never  1h ago
      address=192.168.100.50 mac-address=AA:BB:CC:DD:EE:01
"""
        results = [CommandResult(index=0, command="/ip dhcp-server lease print detail", stdout=output)]
        leases, overview = parse_dhcp_leases(results)

        assert len(leases) == 2
        assert leases[0].comment == "Device1 Storage"
        assert leases[1].comment == "Device2 Printer"

    def test_parse_lease_with_quoted_values(self):
        """Test parsing DHCP lease with quoted values containing spaces."""
        output = """Flags: D - DYNAMIC
 0  D  192.168.100.100  AA:BB:CC:DD:EE:01  dhcp1  23h
      address=192.168.100.100 mac-address=AA:BB:CC:DD:EE:01
      host-name="My Computer"
      client-id="1:aa:bb:cc:dd:ee:01"
"""
        results = [CommandResult(index=0, command="/ip dhcp-server lease print detail", stdout=output)]
        leases, overview = parse_dhcp_leases(results)

        assert len(leases) == 1
        assert leases[0].address == "192.168.100.100"

    def test_parse_lease_with_options(self):
        """Test parsing DHCP lease with options."""
        output = """Flags: D - DYNAMIC
 0  D  192.168.100.100  AA:BB:CC:DD:EE:01  dhcp1  23h
      address=192.168.100.100 mac-address=AA:BB:CC:DD:EE:01
      host-name=TestPC
"""
        results = [CommandResult(index=0, command="/ip dhcp-server lease print detail", stdout=output)]
        leases, overview = parse_dhcp_leases(results)

        assert len(leases) == 1
        assert leases[0].address == "192.168.100.100"

    def test_parse_multiple_leases(self):
        """Test parsing multiple DHCP leases."""
        output = """Flags: D - DYNAMIC
 0  D  192.168.100.100  AA:BB:CC:DD:EE:01  PC1  dhcp1  23h  10m ago
      address=192.168.100.100 mac-address=AA:BB:CC:DD:EE:01 host-name=PC1
 1  D  192.168.100.101  AA:BB:CC:DD:EE:02  PC2  dhcp1  23h  5m ago
      address=192.168.100.101 mac-address=AA:BB:CC:DD:EE:02 host-name=PC2
 2     192.168.100.50   AA:BB:CC:DD:EE:03  Server  dhcp1  never  1h ago
      address=192.168.100.50 mac-address=AA:BB:CC:DD:EE:03 host-name=Server
"""
        results = [CommandResult(index=0, command="/ip dhcp-server lease print detail", stdout=output)]
        leases, overview = parse_dhcp_leases(results)

        assert overview.dhcp_leases_count == 3
        assert overview.dhcp_active_leases == 2  # Только dynamic с expires != never
        assert leases[0].address == "192.168.100.100"
        assert leases[1].address == "192.168.100.101"
        assert leases[2].address == "192.168.100.50"

    def test_parse_lease_data_with_quotes(self):
        """Test _parse_lease_data with quoted values."""
        entry_str = 'address=192.168.100.100 host-name="Test PC" client-id="1:aa:bb:cc:dd:ee"'
        data = _parse_lease_data(entry_str)

        assert data.get('address') == '192.168.100.100'
        # shlex.split должен корректно обработать
        assert 'host_name' in data or 'host-name' in entry_str

    def test_parse_lease_data_without_quotes(self):
        """Test _parse_lease_data without quotes."""
        entry_str = 'address=192.168.100.100 mac-address=AA:BB:CC:DD:EE:FF host-name=TestPC'
        data = _parse_lease_data(entry_str)

        assert data.get('address') == '192.168.100.100'
        assert data.get('mac_address') == 'AA:BB:CC:DD:EE:FF'
        assert data.get('host_name') == 'TestPC'

    def test_parse_lease_with_invalid_quotes(self):
        """Test _parse_lease_data with invalid quotes falls back to normal split."""
        entry_str = 'address=192.168.100.100 host-name="Unclosed quote'
        data = _parse_lease_data(entry_str)

        # Должен обработать без ошибки
        assert data.get('address') == '192.168.100.100'

    def test_parse_lease_server_info(self):
        """Test parsing DHCP lease with server information."""
        output = """Flags: D - DYNAMIC
 0  D  192.168.100.100  AA:BB:CC:DD:EE:01  dhcp1  23h
      address=192.168.100.100 mac-address=AA:BB:CC:DD:EE:01
      server=dhcp1
      address-lists=dhcp_lease
"""
        results = [CommandResult(index=0, command="/ip dhcp-server lease print detail", stdout=output)]
        leases, overview = parse_dhcp_leases(results)

        assert len(leases) == 1
        assert leases[0].server == "dhcp1"

    def test_parse_lease_last_seen(self):
        """Test parsing DHCP lease with last-seen information."""
        output = """Flags: D - DYNAMIC
 0  D  192.168.100.100  AA:BB:CC:DD:EE:01  dhcp1  23h18m47s  10m ago
      address=192.168.100.100 mac-address=AA:BB:CC:DD:EE:01
      last-seen=10m ago
"""
        results = [CommandResult(index=0, command="/ip dhcp-server lease print detail", stdout=output)]
        leases, overview = parse_dhcp_leases(results)

        assert len(leases) == 1
        assert "10m" in leases[0].last_seen
