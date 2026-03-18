"""Tests for JSON report generator.

These tests verify that JSON report generation handles edge cases correctly:
- Empty DNS configuration (dns = None)
- Routing rules as dictionaries (not objects)
- Routes without .active attribute
"""

import json
import pytest
from unittest.mock import MagicMock

from src.config import CommandResult, RouterInfo, BackupResult, SecurityIssue
from src.models import NetworkOverview, DNSInfo, Route, MangleRule, DHCPLease, Container
from src.reports.json_report import JSONReportGenerator


@pytest.fixture
def sample_results():
    """Sample command results for testing."""
    return [
        CommandResult(
            index=0,
            command="/system identity print",
            stdout="name: TestRouter",
            has_error=False,
            duration=1.5
        ),
        CommandResult(
            index=1,
            command="/interface print",
            stdout="*1 name=ether1 running=yes",
            has_error=False,
            duration=2.0
        ),
    ]


@pytest.fixture
def sample_router_info():
    """Sample router info for testing."""
    return RouterInfo(
        identity="TestRouter",
        model="hAP ax^3",
        version="7.22",
        ip="192.168.88.1",
        uptime="5d12h30m"
    )


@pytest.fixture
def sample_security_issues():
    """Sample security issues for testing."""
    return [
        SecurityIssue(
            severity="high",
            category="Security",
            finding="Default admin user",
            description="Default admin user is active",
            recommendation="Disable or rename admin user"
        )
    ]


@pytest.fixture
def sample_backup_result():
    """Sample backup result for testing."""
    return BackupResult(
        status="success",
        timestamp="2026-03-14T12:00:00",
        file_name="backup-20260314_120000.backup",
        file_size=102400
    )


class TestJsonReportWithEmptyDns:
    """Tests for JSON report with empty/None DNS configuration."""

    def test_json_report_with_dns_none(self, tmp_path, sample_results,
                                        sample_router_info, sample_security_issues,
                                        sample_backup_result):
        """Test that dns = None does not cause AttributeError."""
        # Create network overview with dns = None
        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=None,  # Explicitly None
            containers=[],
            mangle_rules=[],
            routing_rules=[],
            routes=[],
            dhcp_leases=[],
            address_lists={}
        )

        # Create generator and generate report
        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        # Verify report was created
        assert report_path.exists()

        # Load and verify DNS section has default values
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        dns_section = report_data['network_overview']['dns']
        assert dns_section['servers'] == []
        assert dns_section['allow_remote'] is False
        assert dns_section['use_doh'] is False
        assert dns_section['doh_server'] == ""
        assert dns_section['cache_size'] == 0
        assert dns_section['static_entries_count'] == 0

    def test_json_report_with_empty_dns_object(self, tmp_path, sample_results,
                                                sample_router_info, sample_security_issues,
                                                sample_backup_result):
        """Test that empty DNSInfo object works correctly."""
        # Create network overview with empty DNSInfo
        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=DNSInfo(),  # Empty DNSInfo object
            containers=[],
            mangle_rules=[],
            routing_rules=[],
            routes=[],
            dhcp_leases=[],
            address_lists={}
        )

        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        assert report_path.exists()

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        dns_section = report_data['network_overview']['dns']
        assert dns_section['servers'] == []
        assert dns_section['allow_remote'] is False
        assert dns_section['use_doh'] is False
        assert dns_section['static_entries_count'] == 0


class TestJsonReportRoutingRulesAsDicts:
    """Tests for routing rules as dictionaries (not objects)."""

    def test_json_report_routing_rules_are_dicts(self, tmp_path, sample_results,
                                                  sample_router_info, sample_security_issues,
                                                  sample_backup_result):
        """Test that routing_rules = [{'src-address': '...'}] works with .get()."""
        # Create network overview with routing rules as dictionaries
        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=DNSInfo(),
            containers=[],
            mangle_rules=[],
            routing_rules=[
                {"src-address": "192.168.1.0/24", "dst-address": "", "routing-mark": "main", "action": "lookup"},
                {"src-address": "", "dst-address": "10.0.0.0/8", "routing-mark": "backup", "action": "lookup", "comment": "Backup route"},
                {"src-address": "172.16.0.0/12", "action": "discard", "disabled": "true"},
            ],
            routes=[],
            dhcp_leases=[],
            address_lists={}
        )

        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        assert report_path.exists()

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        routing_rules = report_data['network_overview']['routing_rules']
        assert len(routing_rules) == 3

        # Verify first rule
        assert routing_rules[0]['src_address'] == "192.168.1.0/24"
        assert routing_rules[0]['dst_address'] == ""
        assert routing_rules[0]['routing_mark'] == "main"
        assert routing_rules[0]['action'] == "lookup"
        assert routing_rules[0]['disabled'] is False

        # Verify second rule with comment
        assert routing_rules[1]['comment'] == "Backup route"

        # Verify third rule with disabled = "true" string
        assert routing_rules[2]['disabled'] is True

    def test_json_report_routing_rules_empty(self, tmp_path, sample_results,
                                              sample_router_info, sample_security_issues,
                                              sample_backup_result):
        """Test that empty routing_rules list works correctly."""
        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=DNSInfo(),
            containers=[],
            mangle_rules=[],
            routing_rules=[],  # Empty list
            routes=[],
            dhcp_leases=[],
            address_lists={}
        )

        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        assert report_path.exists()

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        assert report_data['network_overview']['routing_rules'] == []


class TestJsonReportRouteHasNoActive:
    """Tests for routes without .active attribute."""

    def test_json_report_route_has_no_active(self, tmp_path, sample_results,
                                              sample_router_info, sample_security_issues,
                                              sample_backup_result):
        """Test that Route without .active uses getattr(r, 'active', False)."""
        # Create network overview with Route objects (no .active attribute)
        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=DNSInfo(),
            containers=[],
            mangle_rules=[],
            routing_rules=[],
            routes=[
                Route(
                    dst_address="0.0.0.0/0",
                    gateway="192.168.88.1",
                    routing_mark="main",
                    disabled=False,
                    distance="1",
                    comment="Default route"
                ),
                Route(
                    dst_address="10.0.0.0/8",
                    gateway="192.168.88.2",
                    routing_mark="backup",
                    disabled=True,
                    distance="2",
                    comment="Backup route"
                ),
            ],
            dhcp_leases=[],
            address_lists={}
        )

        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        assert report_path.exists()

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        marked_routes = report_data['network_overview']['marked_routes']
        assert len(marked_routes) == 2

        # Verify first route
        assert marked_routes[0]['dst_address'] == "0.0.0.0/0"
        assert marked_routes[0]['gateway'] == "192.168.88.1"
        assert marked_routes[0]['routing_mark'] == "main"
        assert marked_routes[0]['disabled'] is False
        assert marked_routes[0]['distance'] == "1"
        assert marked_routes[0]['comment'] == "Default route"

        # Verify second route (disabled)
        assert marked_routes[1]['disabled'] is True

    def test_json_report_route_without_routing_mark_excluded(self, tmp_path, sample_results,
                                                              sample_router_info, sample_security_issues,
                                                              sample_backup_result):
        """Test that routes without routing_mark are excluded from marked_routes."""
        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=DNSInfo(),
            containers=[],
            mangle_rules=[],
            routing_rules=[],
            routes=[
                Route(
                    dst_address="0.0.0.0/0",
                    gateway="192.168.88.1",
                    routing_mark="",  # Empty routing_mark
                    disabled=False,
                ),
                Route(
                    dst_address="10.0.0.0/8",
                    gateway="192.168.88.2",
                    routing_mark="backup",  # Has routing_mark
                    disabled=True,
                ),
            ],
            dhcp_leases=[],
            address_lists={}
        )

        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        assert report_path.exists()

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        # Only route with routing_mark should be included
        marked_routes = report_data['network_overview']['marked_routes']
        assert len(marked_routes) == 1
        assert marked_routes[0]['routing_mark'] == "backup"


class TestJsonReportDhcpLeases:
    """Tests for DHCP leases with various attribute configurations."""

    def test_json_report_dhcp_lease_with_host_name(self, tmp_path, sample_results,
                                                    sample_router_info, sample_security_issues,
                                                    sample_backup_result):
        """Test DHCP lease with host_name attribute."""
        # Create a mock lease with host_name
        lease_with_host_name = MagicMock()
        lease_with_host_name.address = "192.168.88.100"
        lease_with_host_name.mac_address = "AA:BB:CC:DD:EE:01"
        lease_with_host_name.host_name = "test-device"
        lease_with_host_name.client_hostname = ""
        lease_with_host_name.address_lists = ""
        lease_with_host_name.dynamic = False
        lease_with_host_name.comment = ""

        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=DNSInfo(),
            containers=[],
            mangle_rules=[],
            routing_rules=[],
            routes=[],
            dhcp_leases=[lease_with_host_name],
            address_lists={}
        )

        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        assert report_path.exists()

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        dhcp_leases = report_data['network_overview']['dhcp_leases']
        assert len(dhcp_leases) == 1
        assert dhcp_leases[0]['host_name'] == "test-device"

    def test_json_report_dhcp_lease_with_client_hostname(self, tmp_path, sample_results,
                                                          sample_router_info, sample_security_issues,
                                                          sample_backup_result):
        """Test DHCP lease with client_hostname (fallback from host_name)."""
        # Create a mock lease with client_hostname but no host_name
        lease_with_client = MagicMock()
        lease_with_client.address = "192.168.88.101"
        lease_with_client.mac_address = "AA:BB:CC:DD:EE:02"
        lease_with_client.host_name = ""  # Empty
        lease_with_client.client_hostname = "client-device"
        lease_with_client.address_lists = ""
        lease_with_client.dynamic = True
        lease_with_client.comment = ""

        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=DNSInfo(),
            containers=[],
            mangle_rules=[],
            routing_rules=[],
            routes=[],
            dhcp_leases=[lease_with_client],
            address_lists={}
        )

        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        assert report_path.exists()

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        dhcp_leases = report_data['network_overview']['dhcp_leases']
        assert len(dhcp_leases) == 1
        # Should fallback to client_hostname when host_name is empty
        assert dhcp_leases[0]['host_name'] == "client-device"


class TestJsonReportMangleRules:
    """Tests for mangle rules serialization."""

    def test_json_report_mangle_rules_serialization(self, tmp_path, sample_results,
                                                     sample_router_info, sample_security_issues,
                                                     sample_backup_result):
        """Test that MangleRule objects are correctly serialized."""
        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=DNSInfo(),
            containers=[],
            mangle_rules=[
                MangleRule(
                    chain="prerouting",
                    action="mark-routing",
                    src_address="192.168.1.0/24",
                    dst_address="",
                    src_address_list="",
                    dst_address_list="",
                    new_routing_mark="route1",
                    disabled=False,
                    comment="Mark traffic from LAN1"
                ),
            ],
            routing_rules=[],
            routes=[],
            dhcp_leases=[],
            address_lists={}
        )

        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        assert report_path.exists()

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        mangle_rules = report_data['network_overview']['mangle_rules']
        assert len(mangle_rules) == 1
        assert mangle_rules[0]['chain'] == "prerouting"
        assert mangle_rules[0]['action'] == "mark-routing"
        assert mangle_rules[0]['src_address'] == "192.168.1.0/24"
        assert mangle_rules[0]['new_routing_mark'] == "route1"
        assert mangle_rules[0]['comment'] == "Mark traffic from LAN1"
        assert mangle_rules[0]['disabled'] is False


class TestJsonReportSummary:
    """Tests for JSON report summary section."""

    def test_json_report_summary_statistics(self, tmp_path, sample_results,
                                            sample_router_info, sample_security_issues,
                                            sample_backup_result):
        """Test that summary statistics are calculated correctly."""
        network_overview = NetworkOverview(
            system_identity="TestRouter",
            system_version="7.22",
            dns=DNSInfo(),
            containers=[
                Container(name="container1", status="running", interface="", image="", root_directory=""),
                Container(name="container2", status="running", interface="", image="", root_directory=""),
                Container(name="container3", status="stopped", interface="", image="", root_directory=""),
            ],  # 3 containers
            mangle_rules=[
                MangleRule(action="mark-routing", chain="prerouting"),
                MangleRule(action="mark-connection", chain="forward"),
            ],  # 2 mangle rules
            routing_rules=[],
            routes=[],
            dhcp_leases=[
                DHCPLease(address="192.168.88.100", mac_address="AA:BB:CC:DD:EE:01"),
                DHCPLease(address="192.168.88.101", mac_address="AA:BB:CC:DD:EE:02"),
                DHCPLease(address="192.168.88.102", mac_address="AA:BB:CC:DD:EE:03"),
                DHCPLease(address="192.168.88.103", mac_address="AA:BB:CC:DD:EE:04"),
                DHCPLease(address="192.168.88.104", mac_address="AA:BB:CC:DD:EE:05"),
            ],  # 5 DHCP leases
            address_lists={}
        )

        generator = JSONReportGenerator(output_dir=tmp_path)
        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result,
            network_overview=network_overview
        )

        assert report_path.exists()

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        summary = report_data['summary']
        assert summary['total_commands'] == 2
        assert summary['failed_commands'] == 0
        assert summary['avg_duration'] == 1.75  # (1.5 + 2.0) / 2
        assert summary['security_issues'] == 1
        assert summary['containers_count'] == 3
        assert summary['dhcp_leases_count'] == 5
        assert summary['mangle_rules_count'] == 2
