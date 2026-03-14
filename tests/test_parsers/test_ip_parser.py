"""Tests for IP parser with real RouterOS v7 output."""

from src.parsers.ip_parser import parse_ip_address_results, _parse_ip_blocks
from src.config import CommandResult


# Реальный формат вывода /ip address print detail из RouterOS v7.22
IP_ADDRESS_DETAIL_OUTPUT = """Flags: X - DISABLED, I - INVALID; D - DYNAMIC; S - SLAVE

 0     address=192.168.100.1/24 network=192.168.100.0 interface=bridge1

       actual-interface=bridge1 vrf=main



 1     ;;; Gateway for CONTAINER1 container network

       address=192.168.101.2/24 network=192.168.101.0 interface=CONTAINER1

       actual-interface=CONTAINER1 vrf=main



 2     ;;; Gateway for CONTAINER2 container network

       address=192.168.102.1/24 network=192.168.102.0 interface=CONTAINER2

       actual-interface=CONTAINER2 vrf=main



 3     ;;; Gateway for CONTAINER3 container network

       address=192.168.103.1/24 network=192.168.103.0 interface=CONTAINER3

       actual-interface=CONTAINER3 vrf=main
"""


class TestIPParser:
    """Tests for IP address parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        addresses, overview = parse_ip_address_results([])
        assert addresses == []
        assert overview.total_ip_addresses == 0

    def test_parse_error_results(self):
        """Test parsing results with errors."""
        results = [CommandResult(index=0, command="/ip address print detail",
                                  stdout="", stderr="error", has_error=True)]
        addresses, overview = parse_ip_address_results(results)
        assert addresses == []

    def test_parse_ip_blocks_real_output(self):
        """Test _parse_ip_blocks with real RouterOS v7 output."""
        blocks = _parse_ip_blocks(IP_ADDRESS_DETAIL_OUTPUT)

        assert len(blocks) >= 3

        # Проверяем что comment распарсился
        found_comment = False
        for block in blocks:
            if block.get('comment'):
                found_comment = True
                break
        assert found_comment

    def test_parse_ip_with_comment(self):
        """Test parsing IP address with comment."""
        output = """ 0     ;;; Gateway for CONTAINER1
       address=192.168.101.2/24 network=192.168.101.0 interface=CONTAINER1
"""
        results = [CommandResult(index=0, command="/ip address print detail", stdout=output)]
        addresses, overview = parse_ip_address_results(results)

        assert len(addresses) == 1
        assert addresses[0].address == "192.168.101.2/24"
        assert addresses[0].comment == "Gateway for CONTAINER1"

    def test_parse_ip_without_comment(self):
        """Test parsing IP address without comment."""
        output = """ 0     address=192.168.100.1/24 network=192.168.100.0 interface=bridge1
"""
        results = [CommandResult(index=0, command="/ip address print detail", stdout=output)]
        addresses, overview = parse_ip_address_results(results)

        assert len(addresses) == 1
        assert addresses[0].address == "192.168.100.1/24"
        assert addresses[0].comment == ""

    def test_parse_multiple_ips(self):
        """Test parsing multiple IP addresses."""
        results = [CommandResult(index=0, command="/ip address print detail",
                                  stdout=IP_ADDRESS_DETAIL_OUTPUT)]
        addresses, overview = parse_ip_address_results(results)

        assert overview.total_ip_addresses >= 3

        # Проверяем что все адреса найдены
        addr_list = [a.address for a in addresses]
        assert "192.168.100.1/24" in addr_list
        assert "192.168.101.2/24" in addr_list
        assert "192.168.102.1/24" in addr_list

    def test_parse_ip_with_actual_interface(self):
        """Test parsing IP address with actual-interface."""
        output = """ 0     address=192.168.100.1/24 network=192.168.100.0 interface=bridge1
       actual-interface=bridge1 vrf=main
"""
        results = [CommandResult(index=0, command="/ip address print detail", stdout=output)]
        addresses, overview = parse_ip_address_results(results)

        assert len(addresses) == 1
        assert addresses[0].actual_interface == "bridge1"

    def test_parse_ip_blocks_simple(self):
        """Test _parse_ip_blocks with simple format."""
        output = """ 0  ;;; First IP
      address=192.168.100.1/24 network=192.168.100.0
 1     address=192.168.101.1/24 network=192.168.101.0
"""
        blocks = _parse_ip_blocks(output)

        assert len(blocks) == 2
        assert blocks[0].get('address') == '192.168.100.1/24'
        assert blocks[0].get('comment') == 'First IP'
