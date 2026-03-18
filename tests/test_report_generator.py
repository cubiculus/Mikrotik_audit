"""Tests for report generator."""

import pytest
from pathlib import Path
import tempfile
import shutil
from unittest.mock import patch

from src.report_generator import ReportGenerator
from src.config import CommandResult, SecurityIssue, RouterInfo, BackupResult
from src.models import NetworkOverview


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    dirpath = tempfile.mkdtemp()
    yield Path(dirpath)
    shutil.rmtree(dirpath)


@pytest.fixture
def sample_results():
    """Create sample command results."""
    return [
        CommandResult(
            index=0,
            command="/system resource print",
            stdout="uptime: 1d2h3m\nfree-memory: 512MiB",
            stderr="",
            has_error=False
        ),
        CommandResult(
            index=1,
            command="/interface print",
            stdout="NAME     TYPE   MTU\nether1   ether  1500",
            stderr="",
            has_error=False
        )
    ]


@pytest.fixture
def sample_security_issues():
    """Create sample security issues."""
    return [
        SecurityIssue(
            severity="High",
            category="Security",
            finding="Test Issue",
            description="Test description",
            recommendation="Test recommendation"
        )
    ]


@pytest.fixture
def sample_router_info():
    """Create sample router info."""
    return RouterInfo(
        identity="test-router",
        model="RB750Gr3",
        version="7.10.5",
        ip="192.168.1.1",
        uptime="1d2h3m"
    )


@pytest.fixture
def sample_backup_result():
    """Create sample backup result."""
    return BackupResult(
        backup_file="test.backup",
        backup_size=1024,
        backup_status="success"
    )


@pytest.fixture
def sample_network_overview():
    """Create sample network overview."""
    overview = NetworkOverview()
    overview.total_interfaces = 5
    overview.total_ip_addresses = 3
    overview.containers_total = 1
    overview.containers_running = 1
    return overview


class TestReportGeneratorInit:
    """Tests for ReportGenerator initialization."""

    def test_init_creates_output_dir(self, temp_dir):
        """Test that init creates output directory."""
        output_dir = temp_dir / "new_dir"
        _ = ReportGenerator(output_dir=output_dir)
        assert output_dir.exists()

    def test_init_with_existing_dir(self, temp_dir):
        """Test initialization with existing directory."""
        _ = ReportGenerator(output_dir=temp_dir)
        assert True

    def test_init_creates_generators(self, temp_dir):
        """Test that init creates format-specific generators."""
        generator = ReportGenerator(output_dir=temp_dir)
        assert generator.html_generator is not None
        assert generator.json_generator is not None
        assert generator.txt_generator is not None
        assert generator.md_generator is not None

    def test_init_with_cache_dir(self, temp_dir):
        """Test initialization with cache directory."""
        cache_dir = temp_dir / "cache"
        generator = ReportGenerator(output_dir=temp_dir, cache_dir=cache_dir)
        assert generator.parser is not None

    def test_init_timestamp_extraction(self, temp_dir):
        """Test timestamp extraction from output dir name."""
        output_dir = temp_dir / "report_20240101_120000"
        output_dir.mkdir()
        generator = ReportGenerator(output_dir=output_dir)
        assert generator.timestamp is not None


class TestReportGeneratorNetworkOverview:
    """Tests for network overview caching."""

    def test_get_network_overview_builds_once(self, temp_dir, sample_results):
        """Test that network overview is built once and cached."""
        generator = ReportGenerator(output_dir=temp_dir)

        with patch.object(generator.parser, 'build_network_overview') as mock_build:
            mock_build.return_value = NetworkOverview()

            generator._get_network_overview(sample_results)
            generator._get_network_overview(sample_results)

            mock_build.assert_called_once()

    def test_get_network_overview_returns_cached(self, temp_dir, sample_results):
        """Test that cached overview is returned."""
        generator = ReportGenerator(output_dir=temp_dir)
        cached_overview = NetworkOverview()
        generator._network_overview = cached_overview

        overview = generator._get_network_overview(sample_results)
        assert overview is cached_overview


class TestGenerateHTMLReport:
    """Tests for HTML report generation."""

    def test_generate_html_report(self, temp_dir, sample_results,
                                   sample_security_issues, sample_router_info):
        """Test HTML report generation."""
        generator = ReportGenerator(output_dir=temp_dir)

        report_path = generator.generate_html_report(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info
        )

        assert report_path.exists()
        assert report_path.suffix == ".html"

    def test_generate_html_report_with_backup(self, temp_dir, sample_results,
                                               sample_security_issues, sample_router_info,
                                               sample_backup_result):
        """Test HTML report generation with backup."""
        generator = ReportGenerator(output_dir=temp_dir)

        report_path = generator.generate_html_report(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result
        )

        assert report_path.exists()

    def test_generate_html_report_with_overview(self, temp_dir, sample_results,
                                                 sample_security_issues, sample_router_info,
                                                 sample_network_overview):
        """Test HTML report generation with pre-built overview."""
        generator = ReportGenerator(output_dir=temp_dir)

        report_path = generator.generate_html_report(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            network_overview=sample_network_overview
        )

        assert report_path.exists()


class TestGenerateJSONReport:
    """Tests for JSON report generation."""

    def test_generate_json_report(self, temp_dir, sample_results,
                                   sample_security_issues, sample_router_info):
        """Test JSON report generation."""
        generator = ReportGenerator(output_dir=temp_dir)

        report_path = generator.generate_json_report(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info
        )

        assert report_path.exists()
        assert report_path.suffix == ".json"

    def test_generate_json_report_with_backup(self, temp_dir, sample_results,
                                               sample_security_issues, sample_router_info,
                                               sample_backup_result):
        """Test JSON report generation with backup."""
        generator = ReportGenerator(output_dir=temp_dir)

        report_path = generator.generate_json_report(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=sample_backup_result
        )

        assert report_path.exists()


class TestGenerateTXTReport:
    """Tests for TXT report generation."""

    def test_generate_txt_report(self, temp_dir, sample_results,
                                  sample_security_issues, sample_router_info):
        """Test TXT report generation."""
        generator = ReportGenerator(output_dir=temp_dir)

        report_path = generator.generate_txt_report(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info
        )

        assert report_path.exists()
        assert report_path.suffix == ".txt"


class TestGenerateMarkdownReport:
    """Tests for Markdown report generation."""

    def test_generate_markdown_report(self, temp_dir, sample_results,
                                       sample_security_issues, sample_router_info):
        """Test Markdown report generation."""
        generator = ReportGenerator(output_dir=temp_dir)

        report_path = generator.generate_markdown_report(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info
        )

        assert report_path.exists()
        assert report_path.suffix == ".md"


class TestGenerateAllReports:
    """Tests for generating all reports."""

    def test_generate_all_reports_default(self, temp_dir, sample_results,
                                           sample_security_issues, sample_router_info):
        """Test generating all reports by default."""
        generator = ReportGenerator(output_dir=temp_dir)

        reports = generator.generate_all_reports(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info
        )

        assert "html" in reports
        assert "json" in reports
        assert "txt" in reports
        assert "md" in reports

        for path in reports.values():
            assert path.exists()

    def test_generate_all_reports_specific_formats(self, temp_dir, sample_results,
                                                    sample_security_issues, sample_router_info):
        """Test generating specific formats."""
        generator = ReportGenerator(output_dir=temp_dir)

        reports = generator.generate_all_reports(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            formats=["html", "json"]
        )

        assert "html" in reports
        assert "json" in reports
        assert "txt" not in reports
        assert "md" not in reports

    def test_generate_all_reports_single_format(self, temp_dir, sample_results,
                                                 sample_security_issues, sample_router_info):
        """Test generating single format."""
        generator = ReportGenerator(output_dir=temp_dir)

        reports = generator.generate_all_reports(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            formats=["txt"]
        )

        assert len(reports) == 1
        assert "txt" in reports

    def test_generate_all_reports_with_overview(self, temp_dir, sample_results,
                                                 sample_security_issues, sample_router_info,
                                                 sample_network_overview):
        """Test generating reports with pre-built overview."""
        generator = ReportGenerator(output_dir=temp_dir)

        reports = generator.generate_all_reports(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            network_overview=sample_network_overview
        )

        assert len(reports) == 4
        for path in reports.values():
            assert path.exists()


class TestReportGeneratorLogging:
    """Tests for report generator logging."""

    def test_generate_html_report_logs(self, temp_dir, sample_results,
                                        sample_security_issues, sample_router_info):
        """Test that HTML report generation is logged."""
        generator = ReportGenerator(output_dir=temp_dir)

        with patch('src.report_generator.logger') as mock_logger:
            generator.generate_html_report(
                results=sample_results,
                security_issues=sample_security_issues,
                router_info=sample_router_info
            )

            mock_logger.info.assert_called()


class TestReportGeneratorEdgeCases:
    """Tests for edge cases in report generator."""

    def test_empty_security_issues(self, temp_dir, sample_results, sample_router_info):
        """Test report generation with no security issues."""
        generator = ReportGenerator(output_dir=temp_dir)

        reports = generator.generate_all_reports(
            results=sample_results,
            security_issues=[],
            router_info=sample_router_info
        )

        assert len(reports) == 4

    def test_empty_results(self, temp_dir, sample_security_issues, sample_router_info):
        """Test report generation with no command results."""
        generator = ReportGenerator(output_dir=temp_dir)

        reports = generator.generate_all_reports(
            results=[],
            security_issues=sample_security_issues,
            router_info=sample_router_info
        )

        assert len(reports) == 4

    def test_none_backup_result(self, temp_dir, sample_results,
                                 sample_security_issues, sample_router_info):
        """Test report generation with None backup result."""
        generator = ReportGenerator(output_dir=temp_dir)

        report_path = generator.generate_html_report(
            results=sample_results,
            security_issues=sample_security_issues,
            router_info=sample_router_info,
            backup_result=None
        )

        assert report_path.exists()
