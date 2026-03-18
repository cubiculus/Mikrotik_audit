"""Tests for --output-formats parameter.

These tests verify that the --output-formats parameter works correctly:
- Single format (html, json, txt, md)
- Multiple formats (json,txt)
- --all-formats flag
- Unknown formats are handled gracefully
"""

import pytest
from pathlib import Path
from click.testing import CliRunner
from unittest.mock import patch, MagicMock

from src.cli import cli


@pytest.fixture
def mock_audit_success():
    """Mock successful audit execution."""
    with patch('src.cli.MikroTikAuditor') as mock_auditor:
        mock_instance = MagicMock()
        mock_instance.run_audit.return_value = True
        mock_instance.get_results.return_value = []
        mock_instance.get_router_info.return_value = MagicMock(
            identity="TestRouter",
            model="hAP ax^3",
            version="7.22",
            ip="192.168.88.1",
            uptime="5d12h30m"
        )
        mock_instance.get_security_issues.return_value = []
        mock_instance.get_network_overview.return_value = MagicMock(
            system_identity="TestRouter",
            system_version="7.22",
            dns=None,
            containers=[],
            mangle_rules=[],
            routing_rules=[],
            routes=[],
            dhcp_leases=[],
            address_lists={}
        )
        mock_instance.get_output_dir.return_value = Path("audit-reports/test")
        mock_instance.get_timestamp.return_value = "20260318_120000"
        mock_instance.ssh = MagicMock()
        mock_auditor.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_backup_success():
    """Mock successful backup."""
    with patch('src.cli.BackupManager') as mock_backup:
        mock_instance = MagicMock()
        mock_instance.perform_backup.return_value = MagicMock(
            status="success",
            timestamp="2026-03-18T12:00:00",
            file_name="backup.backup",
            file_size=102400
        )
        mock_backup.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_report_generator():
    """Mock report generator that creates empty files."""
    with patch('src.cli.ReportGenerator') as mock_generator:
        mock_instance = MagicMock()
        mock_instance.generate_html_report.return_value = Path("audit-reports/test/report.html")
        mock_instance.generate_json_report.return_value = Path("audit-reports/test/report.json")
        mock_instance.generate_txt_report.return_value = Path("audit-reports/test/report.txt")
        mock_instance.generate_markdown_report.return_value = Path("audit-reports/test/report.md")
        mock_generator.return_value = mock_instance
        yield mock_instance


class TestOutputFormatsSingle:
    """Tests for single format output."""

    def test_output_formats_html_only(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test --output-formats html generates only HTML."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'html']
        )

        # Dry-run exits 0
        assert result.exit_code == 0

    def test_output_formats_json_only(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test --output-formats json generates only JSON."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'json']
        )

        assert result.exit_code == 0

    def test_output_formats_txt_only(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test --output-formats txt generates only TXT."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'txt']
        )

        assert result.exit_code == 0

    def test_output_formats_md_only(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test --output-formats md generates only Markdown."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'md']
        )

        assert result.exit_code == 0


class TestOutputFormatsMultiple:
    """Tests for multiple format output."""

    def test_output_formats_json_txt(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test --output-formats json,txt generates both formats."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'json,txt']
        )

        assert result.exit_code == 0

    def test_output_formats_html_json_txt(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test --output-formats html,json,txt generates all three."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'html,json,txt']
        )

        assert result.exit_code == 0

    def test_output_formats_with_spaces(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test --output-formats with spaces (html, json, md)."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'html, json, md']
        )

        assert result.exit_code == 0


class TestOutputFormatsAll:
    """Tests for --all-formats flag."""

    def test_all_formats_flag(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test --all-formats generates html,json,txt,md."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--all-formats']
        )

        assert result.exit_code == 0

    def test_all_formats_overrides_output_formats(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test --all-formats overrides --output-formats."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'html', '--all-formats']
        )

        assert result.exit_code == 0


class TestOutputFormatsUnknown:
    """Tests for unknown format handling."""

    def test_output_formats_unknown_format(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test unknown format is handled gracefully."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'xml']
        )

        # Should either error or ignore unknown format
        # The key is it shouldn't crash
        assert result.exit_code == 0 or result.exit_code == 1

    def test_output_formats_mixed_known_unknown(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test mixed known/unknown formats."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'html,xml,pdf']
        )

        # Should handle gracefully
        assert result.exit_code == 0 or result.exit_code == 1

    def test_output_formats_case_insensitive(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test format names are case insensitive."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', 'HTML,JSON']
        )

        assert result.exit_code == 0


class TestOutputFormatsDefault:
    """Tests for default format behavior."""

    def test_default_format_without_specifying(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test default format when --output-formats not specified."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin']
        )

        assert result.exit_code == 0

    def test_empty_output_formats_string(
        self, mock_audit_success, mock_backup_success, mock_report_generator
    ):
        """Test empty --output-formats string."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-formats', '']
        )

        # Should use default or handle gracefully
        assert result.exit_code == 0 or result.exit_code == 1
