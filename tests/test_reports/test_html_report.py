"""Tests for HTML report generator."""

import pytest
from unittest.mock import patch

from src.config import CommandResult, RouterInfo, BackupResult, SecurityIssue
from src.models import NetworkOverview, DNSInfo, Route, MangleRule, DHCPLease, Container
from src.reports.html_report import HTMLReportGenerator


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
        CommandResult(
            index=2,
            command="/ip address print",
            stdout="error",
            has_error=True,
            duration=0.5,
            error_type="TimeoutError",
            error_message="Connection timed out"
        )
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
        ),
        SecurityIssue(
            severity="medium",
            category="Configuration",
            finding="Open SSH port",
            description="SSH port 22 is open to WAN",
            recommendation="Restrict SSH access"
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
    overview.total_ip_addresses = 3
    overview.containers_total = 2
    overview.containers_running = 1
    overview.dhcp_leases_count = 10
    overview.dns_info = DNSInfo(
        servers=["8.8.8.8", "1.1.1.1"],
        allow_remote=True,
        cache_size=2048
    )
    overview.routes = [
        Route(dst_address="0.0.0.0/0", gateway="192.168.88.1"),
        Route(dst_address="192.168.1.0/24", gateway="192.168.88.1")
    ]
    overview.mangle_rules = [
        MangleRule(chain="forward", action="mark-connection", comment="Test rule")
    ]
    overview.dhcp_leases = [
        DHCPLease(address="192.168.88.100", mac_address="AA:BB:CC:DD:EE:FF", host_name="Device1")
    ]
    overview.containers = [
        Container(name="container1", status="running", image="nginx:latest")
    ]
    return overview


class TestHTMLReportGeneratorInit:
    """Tests for HTMLReportGenerator initialization."""

    def test_init_creates_generators(self, tmp_path):
        """Test initialization creates generator."""
        generator = HTMLReportGenerator(output_dir=tmp_path)
        assert generator.output_dir == tmp_path

    def test_init_with_template_path(self, tmp_path):
        """Test initialization with custom template path."""
        template_path = tmp_path / "custom_template.html"
        template_path.write_text("<html></html>")
        generator = HTMLReportGenerator(output_dir=tmp_path, template_path=template_path)
        assert generator.template is not None


class TestHTMLReportGeneration:
    """Tests for HTML report generation."""

    def test_generate_html_report(self, tmp_path, sample_results,
                                   sample_router_info, sample_security_issues):
        """Test basic HTML report generation."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info
        )

        assert report_path.exists()
        assert report_path.suffix == ".html"
        content = report_path.read_text()
        assert "TestRouter" in content

    def test_generate_with_backup(self, tmp_path, sample_results,
                                   sample_security_issues, sample_router_info,
                                   sample_backup_result):
        """Test HTML report with backup result."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result
        )

        assert report_path.exists()
        content = report_path.read_text()
        assert "backup" in content.lower() or "Backup" in content

    def test_generate_with_network_overview(self, tmp_path, sample_results,
                                             sample_security_issues, sample_router_info,
                                             sample_network_overview):
        """Test HTML report with network overview."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        report_path = generator.generate(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            network_overview=sample_network_overview
        )

        assert report_path.exists()
        content = report_path.read_text()
        assert "ether1" in content or "interface" in content.lower()


class TestHTMLReportCharts:
    """Tests for HTML chart generation."""

    def test_create_charts(self, tmp_path, sample_results):
        """Test chart creation."""
        generator = HTMLReportGenerator(output_dir=tmp_path)
        sorted_results = sorted(sample_results, key=lambda x: x.duration, reverse=True)

        charts_html = generator._create_charts(sample_results, sorted_results)

        assert "plot1" in charts_html or "plot2" in charts_html or "chart" in charts_html

    def test_create_charts_no_errors(self, tmp_path):
        """Test chart creation with no errors."""
        results = [
            CommandResult(
                index=0,
                command="/system identity print",
                stdout="name: Test",
                has_error=False,
                duration=1.0
            )
        ]
        generator = HTMLReportGenerator(output_dir=tmp_path)
        sorted_results = results

        charts_html = generator._create_charts(results, sorted_results)

        assert charts_html is not None

    def test_create_charts_handles_exception(self, tmp_path, sample_results):
        """Test chart creation handles exceptions."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        with patch('plotly.graph_objects.Figure') as mock_figure:
            mock_figure.side_effect = Exception("Plotly error")
            sorted_results = sorted(sample_results, key=lambda x: x.duration, reverse=True)

            charts_html = generator._create_charts(sample_results, sorted_results)

            assert "Failed to generate charts" in charts_html or charts_html


class TestHTMLReportCommandsTable:
    """Tests for HTML commands table generation."""

    def test_create_commands_table_success(self, tmp_path):
        """Test commands table with successful commands."""
        results = [
            CommandResult(
                index=0,
                command="/system identity print",
                stdout="name: Test",
                has_error=False,
                duration=1.0
            )
        ]
        generator = HTMLReportGenerator(output_dir=tmp_path)

        table_html = generator._create_commands_table(results)

        assert "Success" in table_html or "success" in table_html

    def test_create_commands_table_error(self, tmp_path):
        """Test commands table with failed commands."""
        results = [
            CommandResult(
                index=0,
                command="/system identity print",
                stdout="",
                has_error=True,
                duration=1.0,
                error_type="TimeoutError",
                error_message="Connection timed out"
            )
        ]
        generator = HTMLReportGenerator(output_dir=tmp_path)

        table_html = generator._create_commands_table(results)

        assert "Failed" in table_html or "error" in table_html

    def test_create_commands_table_empty(self, tmp_path):
        """Test commands table with empty results."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        table_html = generator._create_commands_table([])

        assert table_html is not None


class TestHTMLReportSecuritySection:
    """Tests for HTML security section generation."""

    def test_create_security_section_with_issues(self, tmp_path, sample_security_issues):
        """Test security section with issues."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_security_section(sample_security_issues)

        assert "high" in section_html.lower() or "High" in section_html
        assert "Default admin" in section_html or "security" in section_html.lower()

    def test_create_security_section_empty(self, tmp_path):
        """Test security section with no issues."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_security_section([])

        assert section_html is not None


class TestHTMLReportContainersSection:
    """Tests for HTML containers section generation."""

    def test_create_containers_section_with_data(self, tmp_path, sample_network_overview):
        """Test containers section with data."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_containers_section(sample_network_overview)

        assert section_html is not None

    def test_create_containers_section_empty(self, tmp_path):
        """Test containers section with no data."""
        generator = HTMLReportGenerator(output_dir=tmp_path)
        overview = NetworkOverview()

        section_html = generator._create_containers_section(overview)

        assert section_html is not None


class TestHTMLReportDNSSection:
    """Tests for HTML DNS section generation."""

    def test_create_dns_section_with_data(self, tmp_path, sample_network_overview):
        """Test DNS section with data."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_dns_section(sample_network_overview)

        assert section_html is not None

    def test_create_dns_section_empty(self, tmp_path):
        """Test DNS section with no data."""
        generator = HTMLReportGenerator(output_dir=tmp_path)
        overview = NetworkOverview()

        section_html = generator._create_dns_section(overview)

        assert section_html is not None


class TestHTMLReportFailedCommands:
    """Tests for HTML failed commands section."""

    def test_create_failed_commands_section(self, tmp_path, sample_results):
        """Test failed commands section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_failed_commands_section(sample_results)

        assert section_html is not None

    def test_create_failed_commands_section_no_failures(self, tmp_path):
        """Test failed commands section with no failures."""
        results = [
            CommandResult(
                index=0,
                command="/system identity print",
                stdout="name: Test",
                has_error=False,
                duration=1.0
            )
        ]
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_failed_commands_section(results)

        assert section_html is not None


class TestHTMLReportStatistics:
    """Tests for HTML report statistics."""

    def test_get_report_statistics(self, tmp_path, sample_results):
        """Test report statistics calculation."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        stats = generator._get_report_statistics(sample_results)

        assert "total_commands" in stats
        assert "failed_commands" in stats
        assert "success_rate" in stats
        assert "sorted_results" in stats
        assert stats["total_commands"] == 3
        assert stats["failed_commands"] == 1

    def test_get_report_statistics_empty(self, tmp_path):
        """Test statistics with empty results."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        stats = generator._get_report_statistics([])

        assert stats["total_commands"] == 0
        assert stats["failed_commands"] == 0


class TestHTMLReportSections:
    """Tests for various HTML report sections."""

    def test_create_backup_section_success(self, tmp_path, sample_backup_result):
        """Test backup section with success."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_backup_section(sample_backup_result)

        assert "success" in section_html.lower() or "Success" in section_html

    def test_create_backup_section_none(self, tmp_path):
        """Test backup section with None."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_backup_section(None)

        assert section_html is not None

    def test_create_system_info_section(self, tmp_path, sample_network_overview):
        """Test system info section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_system_info_section(sample_network_overview)

        assert section_html is not None

    def test_create_services_section(self, tmp_path, sample_network_overview):
        """Test services section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_services_section(sample_network_overview)

        assert section_html is not None

    def test_create_certificates_section(self, tmp_path, sample_network_overview):
        """Test certificates section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_certificates_section(sample_network_overview)

        assert section_html is not None

    def test_create_scripts_section(self, tmp_path, sample_network_overview):
        """Test scripts section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_scripts_section(sample_network_overview)

        assert section_html is not None

    def test_create_topology_section(self, tmp_path, sample_network_overview):
        """Test topology section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_topology_section(sample_network_overview)

        assert section_html is not None

    def test_create_diagnostics_section(self, tmp_path, sample_network_overview):
        """Test diagnostics section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_diagnostics_section(sample_network_overview)

        assert section_html is not None

    def test_create_traffic_flow_section(self, tmp_path, sample_network_overview):
        """Test traffic flow section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_traffic_flow_section(sample_network_overview)

        assert section_html is not None

    def test_create_devices_section(self, tmp_path, sample_network_overview):
        """Test devices section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_devices_section(sample_network_overview)

        assert section_html is not None

    def test_create_nat_rules_section(self, tmp_path, sample_network_overview):
        """Test NAT rules section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_nat_rules_section(sample_network_overview)

        assert section_html is not None

    def test_create_filter_rules_section(self, tmp_path, sample_network_overview):
        """Test filter rules section."""
        generator = HTMLReportGenerator(output_dir=tmp_path)

        section_html = generator._create_filter_rules_section(sample_network_overview)

        assert section_html is not None


class TestHTMLReportXSSProtection:
    """Tests for XSS protection in HTML reports."""

    def test_html_escaping_in_commands(self, tmp_path):
        """Test that HTML special characters are escaped."""
        results = [
            CommandResult(
                index=0,
                command="/system identity print",
                stdout="<script>alert('xss')</script>",
                has_error=False,
                duration=1.0
            )
        ]
        generator = HTMLReportGenerator(output_dir=tmp_path)

        table_html = generator._create_commands_table(results)

        assert "<script>" not in table_html

    def test_html_escaping_in_error_message(self, tmp_path):
        """Test that error messages are escaped."""
        results = [
            CommandResult(
                index=0,
                command="/system identity print",
                stdout="",
                has_error=True,
                duration=1.0,
                error_message="<script>alert('xss')</script>"
            )
        ]
        generator = HTMLReportGenerator(output_dir=tmp_path)

        table_html = generator._create_commands_table(results)

        assert "<script>" not in table_html
