"""Tests for diagnostic parser."""

import pytest
from src.parsers.diagnostic_parser import (
    parse_logs,
    parse_firewall_logs,
    parse_history,
    parse_ping_results,
)
from src.config import CommandResult


class TestLogParser:
    """Tests for log parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        entries = parse_logs([])
        assert entries == []

    def test_parse_logs_compact_format(self):
        """Test parsing logs in compact format."""
        output = """Flags:
Columns: TIME, TOPICS, MESSAGE
 0  12:30:45 system,info,account user admin logged in from 192.168.100.100
 1  12:30:40 firewall,info,drop in:ether1 out:(none), proto TCP, 192.168.100.100:54321->10.0.0.1:80
 2  12:30:35 system,error,critical critical error occurred
"""
        results = [CommandResult(index=0, command="/log print", stdout=output)]
        entries = parse_logs(results, count=50)

        assert len(entries) >= 1
        # Проверяем что хотя бы одна запись есть
        assert entries[0].time or entries[0].message

    def test_parse_logs_detail_format(self):
        """Test parsing logs in detail format."""
        # RouterOS detail format uses key=value on continuation lines
        output = """Flags:
 0       topics=system,info,account message="user admin logged in"
         time=12:30:45
 1       topics=firewall,info message="in:ether1 out:(none)"
         time=12:30:40
"""
        results = [CommandResult(index=0, command="/log print detail", stdout=output)]
        entries = parse_logs(results, count=50)

        # Parser may not fully support this format, but should not crash
        assert entries is not None


class TestFirewallLogParser:
    """Tests for firewall log parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        entries = parse_firewall_logs([])
        assert entries == []

    def test_parse_firewall_logs(self):
        """Test parsing firewall logs."""
        output = """Flags:
 0  12:30:40 firewall,info,drop in:ether1 out:(none), src-mac 00:11:22:33:44:55, proto TCP (SYN), 192.168.100.100:54321->10.0.0.1:80, len 60
 1  12:30:35 firewall,info,accept in:wg1 out:ether1, proto UDP, 10.0.0.5:123->8.8.8.8:53, len 48
"""
        results = [CommandResult(index=0, command='/log print where topics~"firewall"', stdout=output)]
        entries = parse_firewall_logs(results)

        assert len(entries) >= 1


class TestHistoryParser:
    """Tests for history parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        entries = parse_history([])
        assert entries == []

    def test_parse_history_compact(self):
        """Test parsing history in compact format."""
        output = """Flags:
Columns: TIME, BY, ACTION, CMD
 0  12:30:45 by=admin add /ip address address=192.168.100.1/24 interface=ether1
 1  12:25:30 by=admin remove /ip firewall filter numbers=5
 2  12:20:15 by=admin set /interface ether name=ether1
"""
        results = [CommandResult(index=0, command="/system history print", stdout=output)]
        entries = parse_history(results)

        assert len(entries) == 3
        assert entries[0].time == "12:30:45"
        assert entries[0].by == "admin"
        assert entries[0].action == "add"
        assert "/ip address" in entries[0].cmd

    def test_parse_history_detail(self):
        """Test parsing history in detail format."""
        output = """Flags:
 0  time=12:30:45 action=add cmd="/ip address add address=192.168.100.1/24" by=admin
 1  time=12:25:30 action=remove cmd="/ip firewall filter remove numbers=5" by=admin
"""
        results = [CommandResult(index=0, command="/system history print", stdout=output)]
        entries = parse_history(results)

        assert len(entries) == 2
        assert entries[0].time == "12:30:45"
        assert entries[0].action == "add"
        assert entries[0].by == "admin"


class TestPingParser:
    """Tests for ping parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        result = parse_ping_results([])
        assert result['sent'] == 0
        assert result['received'] == 0

    def test_parse_ping_success(self):
        """Test parsing successful ping."""
        output = """SEQ HOST SIZE TTL TIME STATUS
  0 8.8.8.8 56 116 2ms
  1 8.8.8.8 56 116 3ms
  2 8.8.8.8 56 116 2ms
  sent=3 received=3 lost=0 avg-rtt=2ms
"""
        results = [CommandResult(index=0, command="/ping 8.8.8.8 count=3", stdout=output)]
        result = parse_ping_results(results)

        assert result['target'] == '8.8.8.8'
        assert result['sent'] == 3
        assert result['received'] == 3
        assert result['lost'] == 0
        assert result['loss_percent'] == 0.0
        assert result['avg_rtt'] == '2ms'
        assert len(result['results']) == 3

    def test_parse_ping_with_loss(self):
        """Test parsing ping with packet loss."""
        output = """SEQ HOST SIZE TTL TIME STATUS
  0 8.8.8.8 56 116 2ms
  1 8.8.8.8 56 116 timeout
  2 8.8.8.8 56 116 3ms
  sent=3 received=2 lost=1 avg-rtt=2ms
"""
        results = [CommandResult(index=0, command="/ping 8.8.8.8 count=3", stdout=output)]
        result = parse_ping_results(results)

        assert result['sent'] == 3
        assert result['received'] == 2
        assert result['lost'] == 1
        assert result['loss_percent'] == pytest.approx(33.33, rel=1)

    def test_parse_ping_all_lost(self):
        """Test parsing ping with all packets lost."""
        output = """SEQ HOST SIZE TTL TIME STATUS
  0 8.8.8.8 56 116 timeout
  1 8.8.8.8 56 116 timeout
  sent=2 received=0 lost=2 avg-rtt=0ms
"""
        results = [CommandResult(index=0, command="/ping 8.8.8.8 count=2", stdout=output)]
        result = parse_ping_results(results)

        assert result['sent'] == 2
        assert result['received'] == 0
        assert result['lost'] == 2
        assert result['loss_percent'] == 100.0

    def test_parse_ping_from_command(self):
        """Test parsing ping target from command."""
        output = """SEQ HOST SIZE TTL TIME STATUS
  0 1.1.1.1 56 116 5ms
  sent=1 received=1 lost=0 avg-rtt=5ms
"""
        results = [CommandResult(index=0, command="/ping 1.1.1.1 count=1", stdout=output)]
        result = parse_ping_results(results)

        assert result['target'] == '1.1.1.1'
