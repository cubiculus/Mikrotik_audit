"""Tests for interface parser."""

from src.parsers.interface_parser import parse_interface_stats, _parse_detail_blocks, _parse_stats_blocks, _parse_column_stats
from src.config import CommandResult
from .test_fixtures import INTERFACE_STATS_OUTPUT, INTERFACE_DETAIL_OUTPUT


class TestInterfaceParser:
    """Tests for interface parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        interfaces, overview = parse_interface_stats([])
        assert interfaces == []
        assert overview.total_interfaces == 0
        assert overview.active_interfaces == 0

    def test_parse_error_results(self):
        """Test parsing results with errors."""
        results = [CommandResult(index=0, command="/interface print", stdout="", stderr="error", has_error=True)]
        interfaces, overview = parse_interface_stats(results)
        assert interfaces == []

    def test_parse_detail_blocks_real_output(self):
        """Test _parse_detail_blocks function with real RouterOS v7 output."""
        blocks = _parse_detail_blocks(INTERFACE_DETAIL_OUTPUT)

        assert len(blocks) >= 1
        # Проверяем что comment распарсился
        found_comment = False
        for name, data in blocks.items():
            if data.get('comment'):
                found_comment = True
                break
        assert found_comment

    def test_parse_detail_blocks_simple(self):
        """Test _parse_detail_blocks with simple format."""
        output = """ 0  R  ;;; Main Interface
      name=ether1 type=ether mtu=1500
      running=yes rx-byte=1000 tx-byte=2000
"""
        blocks = _parse_detail_blocks(output)

        assert "ether1" in blocks
        assert blocks["ether1"].get("comment") == "Main Interface"
        assert blocks["ether1"].get("type") == "ether"

    def test_parse_stats_blocks_simple(self):
        """Test _parse_stats_blocks with simple key=value format."""
        output = """ 0  R  name=ether1 rx-byte=1000 tx-byte=2000 rx-packet=100 tx-packet=200
 1  R  name=ether2 rx-byte=500 tx-byte=600 rx-packet=50 tx-packet=60
"""
        stats = _parse_stats_blocks(output)

        assert "ether1" in stats
        assert stats["ether1"]["rx-byte"] == "1000"
        assert stats["ether1"]["tx-byte"] == "2000"
        assert "ether2" in stats

    def test_parse_column_stats(self):
        """Test _parse_column_stats with real RouterOS v7 column format."""
        lines = INTERFACE_STATS_OUTPUT.split('\n')
        stats = _parse_column_stats(lines)

        # Должны найтись интерфейсы
        assert len(stats) >= 1
        assert "ether1" in stats

        # Проверяем что числа распарсились (с тысячными разделителями)
        rx_byte = int(stats["ether1"]["rx-byte"])
        tx_byte = int(stats["ether1"]["tx-byte"])
        assert rx_byte > 2000000000  # 2 360 330 144
        assert tx_byte > 500000000   # 572 441 255

    def test_parse_stats_format_real(self):
        """Test parsing stats format (real RouterOS v7 output)."""
        results = [CommandResult(index=0, command="/interface print stats", stdout=INTERFACE_STATS_OUTPUT)]
        interfaces, overview = parse_interface_stats(results)

        # Должны быть интерфейсы из колоночного формата
        assert overview.total_interfaces >= 1

        # Ищем ether1 в списке (сортировка по имени)
        ether1 = None
        for iface in interfaces:
            if iface.name == "ether1":
                ether1 = iface
                break

        assert ether1 is not None
        assert ether1.rx_byte > 2000000000
        assert ether1.tx_byte > 500000000

    def test_parse_combined_detail_and_stats(self):
        """Test parsing combined detail and stats output."""
        detail = """ 0  R  ;;; WAN Interface
      name=ether1 type=ether mtu=1500 mac-address=AA:BB:CC:DD:EE:01
      running=yes
"""
        stats = """Flags: X - DISABLED; R - RUNNING
Columns: NAME, RX-BYTE, TX-BYTE
 0  R  ether1  1000000  2000000  10000
"""
        results = [
            CommandResult(index=0, command="/interface print detail", stdout=detail),
            CommandResult(index=1, command="/interface print stats", stdout=stats),
        ]
        interfaces, overview = parse_interface_stats(results)

        assert overview.total_interfaces == 1
        assert interfaces[0].name == "ether1"
        assert interfaces[0].type == "ether"
        assert interfaces[0].mtu == 1500
        assert interfaces[0].mac_address == "AA:BB:CC:DD:EE:01"
        assert interfaces[0].rx_byte == 1000000
        assert interfaces[0].tx_byte == 2000000
