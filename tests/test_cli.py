"""Tests for cli module."""

from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from src.cli import cli


class TestCliPrompts:
    """Tests for CLI prompts and authentication."""

    def test_prompts_for_password_when_no_env(self):
        """Test that CLI prompts for password when no env var and no SSH key."""
        runner = CliRunner()

        # Mock environment to ensure no password is set
        with patch.dict('os.environ', {}, clear=True):
            with patch('src.cli.MikroTikAuditor') as mock_auditor:
                # Setup mock auditor instance
                mock_instance = MagicMock()
                mock_instance.run_audit.return_value = True
                mock_instance.get_results.return_value = []
                mock_instance.get_router_info.return_value = {'version': '7.10'}
                mock_instance.get_security_issues.return_value = []
                mock_instance.get_network_overview.return_value = {}
                mock_instance.get_output_dir.return_value = MagicMock()
                mock_instance.get_timestamp.return_value = '20260318_120000'
                mock_auditor.return_value = mock_instance

                # Mock BackupManager
                with patch('src.cli.BackupManager') as mock_backup:
                    mock_backup_instance = MagicMock()
                    mock_backup.return_value = mock_backup_instance

                    # Mock ReportGenerator
                    with patch('src.cli.ReportGenerator') as mock_report:
                        mock_report_instance = MagicMock()
                        mock_report_instance.generate_html_report.return_value = MagicMock()
                        mock_report.return_value = mock_report_instance

                        # Simulate user entering password when prompted
                        # Note: --dry-run is used to avoid actual SSH connection,
                        # but we need to test password prompt in real mode
                        result = runner.invoke(cli, ['audit'], input='testpassword\n')

                        # Should have prompted for password
                        assert 'SSH Password' in result.output
                        assert result.exit_code == 0


class TestCliExitCodes:
    """Tests for CLI exit codes."""

    def test_exits_1_on_audit_failure(self):
        """Test that CLI exits with code 1 when audit fails."""
        runner = CliRunner()

        with patch.dict('os.environ', {'MIKROTIK_PASSWORD': 'testpass'}):
            with patch('src.cli.MikroTikAuditor') as mock_auditor:
                # Setup mock to simulate audit failure
                mock_instance = MagicMock()
                mock_instance.run_audit.return_value = False  # Audit fails
                mock_auditor.return_value = mock_instance

                result = runner.invoke(cli, ['audit', '--router-ip', '192.168.100.1'])

                # Should exit with code 1 on audit failure
                assert result.exit_code == 1


class TestCliRedactWarning:
    """Tests for CLI redact warning."""

    def test_redact_warning_shown_when_flag_not_set(self):
        """Test that warning is shown when --redact flag is not set."""
        runner = CliRunner()

        with patch.dict('os.environ', {'MIKROTIK_PASSWORD': 'testpass'}):
            with patch('src.cli.MikroTikAuditor') as mock_auditor:
                # Setup mock auditor instance
                mock_instance = MagicMock()
                mock_instance.run_audit.return_value = True
                mock_instance.get_results.return_value = []
                mock_instance.get_router_info.return_value = {'version': '7.10'}
                mock_instance.get_security_issues.return_value = []
                mock_instance.get_network_overview.return_value = {}
                mock_instance.get_output_dir.return_value = MagicMock()
                mock_instance.get_timestamp.return_value = '20260318_120000'
                mock_auditor.return_value = mock_instance

                # Mock BackupManager
                with patch('src.cli.BackupManager') as mock_backup:
                    mock_backup_instance = MagicMock()
                    mock_backup.return_value = mock_backup_instance

                    # Mock ReportGenerator
                    with patch('src.cli.ReportGenerator') as mock_report:
                        mock_report_instance = MagicMock()
                        mock_report_instance.generate_html_report.return_value = MagicMock()
                        mock_report.return_value = mock_report_instance

                        # Run without --redact flag
                        result = runner.invoke(cli, ['audit', '--router-ip', '192.168.100.1'])

                        # Should show warning about sensitive data
                        assert 'WARNING' in result.output or 'WARNING' in result.stderr
                        assert 'redact' in result.output.lower() or 'redact' in result.stderr.lower()
