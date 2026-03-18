"""Tests for --dry-run parameter.

These tests verify that --dry-run mode works correctly:
- Exits with code 0
- Does not connect to router
- Shows list of commands that would be executed
- Does not generate report files
"""

from click.testing import CliRunner
from unittest.mock import patch

from src.cli import cli


class TestDryRunExitCodes:
    """Tests for --dry-run exit codes."""

    def test_dry_run_exits_zero(self):
        """Test that --dry-run exits with code 0."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin']
        )

        assert result.exit_code == 0, f"Expected exit code 0, got {result.exit_code}. Output: {result.output}"

    def test_dry_run_exits_zero_with_router_ip(self):
        """Test that --dry-run exits with code 0 with router IP."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--router-ip', '192.168.100.1']
        )

        assert result.exit_code == 0

    def test_dry_run_exits_zero_with_all_options(self):
        """Test that --dry-run exits with code 0 with all options."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                'audit', '--dry-run',
                '--ssh-user', 'admin',
                '--router-ip', '192.168.100.1',
                '--audit-level', 'Standard',
                '--output-formats', 'html,json'
            ]
        )

        assert result.exit_code == 0


class TestDryRunNoConnection:
    """Tests that --dry-run does not connect to router."""

    def test_dry_run_no_ssh_connection(self):
        """Test that --dry-run does not attempt SSH connection."""
        runner = CliRunner()

        with patch('src.cli.MikroTikAuditor') as mock_auditor:
            # Don't setup any mock - if code tries to connect, it will fail
            result = runner.invoke(
                cli,
                ['audit', '--dry-run', '--ssh-user', 'admin']
            )

            # Should exit before attempting connection
            assert result.exit_code == 0
            # Auditor should not be instantiated
            mock_auditor.assert_not_called()

    def test_dry_run_no_backup_attempt(self):
        """Test that --dry-run does not attempt backup."""
        runner = CliRunner()

        with patch('src.cli.BackupManager') as mock_backup:
            result = runner.invoke(
                cli,
                ['audit', '--dry-run', '--ssh-user', 'admin']
            )

            assert result.exit_code == 0
            # BackupManager should not be instantiated
            mock_backup.assert_not_called()

    def test_dry_run_no_report_generation(self):
        """Test that --dry-run does not generate reports."""
        runner = CliRunner()

        with patch('src.cli.ReportGenerator') as mock_report:
            result = runner.invoke(
                cli,
                ['audit', '--dry-run', '--ssh-user', 'admin']
            )

            assert result.exit_code == 0
            # ReportGenerator should not be instantiated
            mock_report.assert_not_called()


class TestDryRunShowsCommands:
    """Tests that --dry-run shows commands that would be executed."""

    def test_dry_run_shows_commands_header(self):
        """Test that --dry-run shows commands header."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin']
        )

        assert result.exit_code == 0
        # Should show some indication of commands
        assert (
            'Commands' in result.output or
            'commands' in result.output or
            '/' in result.output  # RouterOS commands start with /
        )

    def test_dry_run_shows_system_commands(self):
        """Test that --dry-run shows system commands."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin']
        )

        assert result.exit_code == 0
        # Should show system-related commands
        assert (
            '/system' in result.output or
            '/interface' in result.output or
            '/ip' in result.output
        )

    def test_dry_run_shows_audit_level(self):
        """Test that --dry-run shows audit level."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--audit-level', 'Comprehensive']
        )

        assert result.exit_code == 0
        # Should mention the audit level
        assert 'Comprehensive' in result.output or 'audit' in result.output.lower()


class TestDryRunNoReports:
    """Tests that --dry-run does not create report files."""

    def test_dry_run_no_html_report(self, tmp_path):
        """Test that --dry-run does not create HTML report."""
        runner = CliRunner()
        output_dir = tmp_path / "reports"

        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-dir', str(output_dir)]
        )

        assert result.exit_code == 0
        # No files should be created
        assert not output_dir.exists() or len(list(output_dir.glob('*.html'))) == 0

    def test_dry_run_no_json_report(self, tmp_path):
        """Test that --dry-run does not create JSON report."""
        runner = CliRunner()
        output_dir = tmp_path / "reports"

        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-dir', str(output_dir)]
        )

        assert result.exit_code == 0
        # No JSON files should be created
        assert not output_dir.exists() or len(list(output_dir.glob('*.json'))) == 0

    def test_dry_run_no_directory_created(self, tmp_path):
        """Test that --dry-run does not create output directory."""
        runner = CliRunner()
        output_dir = tmp_path / "new_reports"

        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--output-dir', str(output_dir)]
        )

        assert result.exit_code == 0
        # Directory should not be created
        assert not output_dir.exists()


class TestDryRunConfiguration:
    """Tests for --dry-run configuration display."""

    def test_dry_run_shows_router_ip(self):
        """Test that --dry-run shows configured router IP."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--router-ip', '192.168.100.1']
        )

        assert result.exit_code == 0
        assert '192.168.100.1' in result.output

    def test_dry_run_shows_ssh_user(self):
        """Test that --dry-run shows SSH user."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'testuser']
        )

        assert result.exit_code == 0
        assert 'testuser' in result.output or 'user' in result.output.lower()

    def test_dry_run_shows_ssh_port(self):
        """Test that --dry-run shows SSH port."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--ssh-port', '2222']
        )

        assert result.exit_code == 0
        assert '2222' in result.output

    def test_dry_run_shows_audit_configuration(self):
        """Test that --dry-run shows audit configuration summary."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin']
        )

        assert result.exit_code == 0
        # Should show some configuration summary
        assert (
            'DRY' in result.output.upper() or
            'dry-run' in result.output.lower() or
            'would' in result.output.lower() or
            'Configuration' in result.output
        )


class TestDryRunWithOtherFlags:
    """Tests for --dry-run combined with other flags."""

    def test_dry_run_with_verbose(self):
        """Test that --dry-run works with --verbose."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--verbose']
        )

        assert result.exit_code == 0

    def test_dry_run_with_redact(self):
        """Test that --dry-run works with --redact."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--redact']
        )

        assert result.exit_code == 0

    def test_dry_run_with_quiet(self):
        """Test that --dry-run works with --quiet."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--quiet']
        )

        assert result.exit_code == 0

    def test_dry_run_with_skip_security(self):
        """Test that --dry-run works with --skip-security."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--skip-security']
        )

        assert result.exit_code == 0

    def test_dry_run_with_no_backup(self):
        """Test that --dry-run works with --no-backup."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--ssh-user', 'admin', '--no-backup']
        )

        assert result.exit_code == 0
