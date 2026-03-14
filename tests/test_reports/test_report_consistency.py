"""Tests for report consistency between formats.

These tests verify that data is consistent across HTML, TXT, JSON, and Markdown reports.
"""

import pytest
import json
from unittest.mock import MagicMock

from src.config import CommandResult, RouterInfo, BackupResult, SecurityIssue
from src.models import NetworkOverview, NetworkInterface, IPAddress
from src.reports.html_report import HTMLReportGenerator
from src.reports.txt_report import TXTReportGenerator
from src.reports.json_report import JSONReportGenerator
from src.reports.markdown_report import MarkdownReportGenerator


@pytest.fixture
def sample_results():
    """Sample command results for testing."""
    return [
        CommandResult(
            index=0,
            command="/system identity print",
            stdout="name: TestRouter",
            has_error=False
        ),
        CommandResult(
            index=1,
            command="/interface print",
            stdout="*1 name=ether1 running=yes",
            has_error=False
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


@pytest.fixture
def sample_network_overview():
    """Sample network overview for testing."""
    overview = NetworkOverview()
    overview.total_interfaces = 5
    overview.active_interfaces = 4
    overview.total_ip_addresses = 3
    overview.dhcp_leases_count = 10
    overview.dhcp_active_leases = 8
    overview.interfaces = [
        NetworkInterface(name="ether1", type="ether", running=True),
        NetworkInterface(name="ether2", type="ether", running=True),
    ]
    overview.ip_addresses = [
        IPAddress(address="192.168.88.1/24", interface="bridge-local"),
    ]
    return overview


class TestReportConsistency:
    """Tests for consistency between report formats."""

    def test_all_reports_generated(self, tmp_path, sample_results, sample_router_info,
                                    sample_security_issues, sample_backup_result,
                                    sample_network_overview):
        """Test that all report formats can be generated."""
        # Create generators
        html_gen = HTMLReportGenerator(tmp_path)
        txt_gen = TXTReportGenerator(tmp_path)
        json_gen = JSONReportGenerator(tmp_path)
        md_gen = MarkdownReportGenerator(tmp_path)

        # Generate all reports
        html_path = html_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        txt_path = txt_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        json_path = json_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        md_path = md_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )

        # Verify all files exist
        assert html_path.exists()
        assert txt_path.exists()
        assert json_path.exists()
        assert md_path.exists()

    def test_router_info_consistency(self, tmp_path, sample_results, sample_router_info,
                                      sample_security_issues, sample_backup_result,
                                      sample_network_overview):
        """Test that router info is consistent across reports."""
        # Generate reports
        html_gen = HTMLReportGenerator(tmp_path)
        txt_gen = TXTReportGenerator(tmp_path)
        json_gen = JSONReportGenerator(tmp_path)

        html_path = html_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        txt_path = txt_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        json_path = json_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )

        # Read reports
        html_content = html_path.read_text()
        txt_content = txt_path.read_text()
        with open(json_path, 'r') as f:
            json_content = json.load(f)

        # Check router identity is in all reports
        assert sample_router_info.identity in html_content
        assert sample_router_info.identity in txt_content
        assert json_content['router_info']['identity'] == sample_router_info.identity

        # Check model is in all reports
        assert sample_router_info.model in html_content
        assert sample_router_info.model in txt_content
        assert json_content['router_info']['model'] == sample_router_info.model

    def test_security_issues_consistency(self, tmp_path, sample_results, sample_router_info,
                                          sample_security_issues, sample_backup_result,
                                          sample_network_overview):
        """Test that security issues are consistent across reports."""
        html_gen = HTMLReportGenerator(tmp_path)
        txt_gen = TXTReportGenerator(tmp_path)
        json_gen = JSONReportGenerator(tmp_path)

        html_path = html_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        txt_path = txt_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        json_path = json_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )

        # Read reports
        html_content = html_path.read_text()
        txt_content = txt_path.read_text()
        with open(json_path, 'r') as f:
            json_content = json.load(f)

        # Check security issue finding is in all reports
        issue = sample_security_issues[0]
        assert issue.finding in html_content
        assert issue.finding in txt_content
        assert len(json_content['security_issues']) == 1
        assert json_content['security_issues'][0]['finding'] == issue.finding

    def test_command_results_consistency(self, tmp_path, sample_results, sample_router_info,
                                          sample_security_issues, sample_backup_result,
                                          sample_network_overview):
        """Test that command results are consistent across reports."""
        html_gen = HTMLReportGenerator(tmp_path)
        txt_gen = TXTReportGenerator(tmp_path)
        json_gen = JSONReportGenerator(tmp_path)

        _html_path = html_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        _txt_path = txt_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        json_path = json_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )

        # Read JSON report
        with open(json_path, 'r') as f:
            json_content = json.load(f)

        # Check command count matches
        assert json_content['total_commands'] == len(sample_results)
        assert json_content['failed_commands'] == 0
        assert json_content['success_rate'] == 100.0

    def test_network_overview_consistency(self, tmp_path, sample_results, sample_router_info,
                                           sample_security_issues, sample_backup_result,
                                           sample_network_overview):
        """Test that network overview is consistent across reports."""
        html_gen = HTMLReportGenerator(tmp_path)
        json_gen = JSONReportGenerator(tmp_path)

        html_path = html_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )
        json_path = json_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )

        # Read reports
        html_content = html_path.read_text()
        with open(json_path, 'r') as f:
            json_content = json.load(f)

        # Check network overview data
        assert str(sample_network_overview.total_interfaces) in html_content
        assert json_content['network_overview']['total_interfaces'] == sample_network_overview.total_interfaces
        assert json_content['network_overview']['active_interfaces'] == sample_network_overview.active_interfaces


class TestHTMLReportSections:
    """Tests for HTML report sections."""

    def test_system_info_section(self, tmp_path, sample_results, sample_router_info,
                                  sample_security_issues, sample_backup_result,
                                  sample_network_overview):
        """Test that system info section is generated."""
        # Add system resource data
        sample_network_overview.system_resource = MagicMock()
        sample_network_overview.system_resource.cpu_load = [5, 10, 8, 12]
        sample_network_overview.system_resource.free_memory = 512 * 1024 * 1024
        sample_network_overview.system_resource.total_memory = 1024 * 1024 * 1024
        sample_network_overview.system_resource.uptime = "5d12h"
        sample_network_overview.system_resource.version = "7.22"

        html_gen = HTMLReportGenerator(tmp_path)
        html_path = html_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )

        content = html_path.read_text()
        assert "System Information" in content or "system" in content.lower()

    def test_services_section(self, tmp_path, sample_results, sample_router_info,
                               sample_security_issues, sample_backup_result,
                               sample_network_overview):
        """Test that services section is generated."""
        from src.models import Service
        sample_network_overview.services = [
            Service(name="ssh", port=22, disabled=False, tls_required=True),
            Service(name="www", port=80, disabled=False),
        ]

        html_gen = HTMLReportGenerator(tmp_path)
        html_path = html_gen.generate(
            sample_results, sample_security_issues, sample_router_info,
            sample_backup_result, sample_network_overview
        )

        content = html_path.read_text()
        assert "Service" in content or "ssh" in content.lower()
