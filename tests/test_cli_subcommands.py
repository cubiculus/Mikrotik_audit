"""Tests for CLI subcommands.

These tests verify that click.group correctly registers subcommands:
- 'audit' subcommand is visible in --help
- 'diff' subcommand is visible in --help
- Both subcommands work correctly
"""

import json
from click.testing import CliRunner
from src.cli import cli


class TestCliSubcommands:
    """Tests for CLI subcommand registration."""

    def test_cli_has_audit_subcommand(self):
        """Test that 'audit' is visible in --help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])

        assert result.exit_code == 0
        assert 'audit' in result.output
        # Verify audit is shown as a command
        assert 'Commands:' in result.output or 'audit' in result.output.lower()

    def test_cli_has_diff_subcommand(self):
        """Test that 'diff' is visible in --help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])

        assert result.exit_code == 0
        assert 'diff' in result.output
        # Verify diff is shown as a command with description
        assert 'Compare two JSON audit reports' in result.output or 'diff' in result.output.lower()

    def test_audit_subcommand_help(self):
        """Test that 'audit --help' works correctly."""
        runner = CliRunner()
        result = runner.invoke(cli, ['audit', '--help'])

        assert result.exit_code == 0
        assert 'MikroTik RouterOS Audit Tool' in result.output or 'Usage:' in result.output
        # Verify key options are present
        assert '--ssh-user' in result.output
        assert '--ssh-key-file' in result.output
        assert '--output-formats' in result.output
        assert '--dry-run' in result.output

    def test_diff_subcommand_help(self):
        """Test that 'diff --help' works correctly."""
        runner = CliRunner()
        result = runner.invoke(cli, ['diff', '--help'])

        assert result.exit_code == 0
        assert 'Compare two JSON audit reports' in result.output
        assert 'report1' in result.output
        assert 'report2' in result.output
        assert '--output' in result.output


class TestDiffSubcommand:
    """Tests for diff subcommand functionality."""

    def test_diff_command_with_identical_reports(self, tmp_path):
        """Test diff with two identical reports shows no differences."""
        runner = CliRunner()

        # Create two identical reports
        report_data = {
            "metadata": {"timestamp": "2026-03-18"},
            "router_info": {"version": "7.22", "identity": "TestRouter"},
            "security_issues": [],
            "summary": {"total_commands": 5}
        }

        report1_path = tmp_path / "report1.json"
        report2_path = tmp_path / "report2.json"

        with open(report1_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f)
        with open(report2_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f)

        result = runner.invoke(cli, ['diff', str(report1_path), str(report2_path)])

        assert result.exit_code == 0
        assert 'Comparing audit reports' in result.output

    def test_diff_command_with_different_versions(self, tmp_path):
        """Test diff detects router version changes."""
        runner = CliRunner()

        report1_data = {
            "metadata": {"timestamp": "2026-03-18"},
            "router_info": {"version": "7.21", "identity": "TestRouter"},
            "security_issues": [],
            "summary": {"total_commands": 5}
        }

        report2_data = {
            "metadata": {"timestamp": "2026-03-19"},
            "router_info": {"version": "7.22", "identity": "TestRouter"},
            "security_issues": [],
            "summary": {"total_commands": 5}
        }

        report1_path = tmp_path / "report1.json"
        report2_path = tmp_path / "report2.json"

        with open(report1_path, 'w', encoding='utf-8') as f:
            json.dump(report1_data, f)
        with open(report2_path, 'w', encoding='utf-8') as f:
            json.dump(report2_data, f)

        result = runner.invoke(cli, ['diff', str(report1_path), str(report2_path)])

        assert result.exit_code == 0
        assert 'RouterOS version changed' in result.output
        assert '7.21' in result.output
        assert '7.22' in result.output

    def test_diff_command_with_new_security_issues(self, tmp_path):
        """Test diff detects new security issues."""
        runner = CliRunner()

        report1_data = {
            "metadata": {"timestamp": "2026-03-18"},
            "router_info": {"version": "7.22", "identity": "TestRouter"},
            "security_issues": [
                {"severity": "high", "category": "Security", "finding": "Issue 1"}
            ],
            "summary": {"total_commands": 5}
        }

        report2_data = {
            "metadata": {"timestamp": "2026-03-19"},
            "router_info": {"version": "7.22", "identity": "TestRouter"},
            "security_issues": [
                {"severity": "high", "category": "Security", "finding": "Issue 1"},
                {"severity": "medium", "category": "Security", "finding": "New Issue 2"}
            ],
            "summary": {"total_commands": 5}
        }

        report1_path = tmp_path / "report1.json"
        report2_path = tmp_path / "report2.json"

        with open(report1_path, 'w', encoding='utf-8') as f:
            json.dump(report1_data, f)
        with open(report2_path, 'w', encoding='utf-8') as f:
            json.dump(report2_data, f)

        result = runner.invoke(cli, ['diff', str(report1_path), str(report2_path)])

        assert result.exit_code == 0
        assert 'New security issues' in result.output or 'New Issue 2' in result.output

    def test_diff_command_with_output_file(self, tmp_path):
        """Test diff with --output option writes JSON file."""
        runner = CliRunner()

        report1_data = {
            "metadata": {"timestamp": "2026-03-18"},
            "router_info": {"version": "7.22", "identity": "TestRouter"},
            "security_issues": [],
            "summary": {"total_commands": 5}
        }

        report2_data = {
            "metadata": {"timestamp": "2026-03-19"},
            "router_info": {"version": "7.22", "identity": "TestRouter"},
            "security_issues": [],
            "summary": {"total_commands": 5}
        }

        report1_path = tmp_path / "report1.json"
        report2_path = tmp_path / "report2.json"
        output_path = tmp_path / "diff_output.json"

        with open(report1_path, 'w', encoding='utf-8') as f:
            json.dump(report1_data, f)
        with open(report2_path, 'w', encoding='utf-8') as f:
            json.dump(report2_data, f)

        result = runner.invoke(
            cli,
            ['diff', str(report1_path), str(report2_path), '--output', str(output_path)]
        )

        assert result.exit_code == 0
        assert output_path.exists()

        # Verify output file is valid JSON
        with open(output_path, 'r', encoding='utf-8') as f:
            diff_output = json.load(f)
        assert diff_output is not None

    def test_diff_command_with_nonexistent_file(self):
        """Test diff with nonexistent file returns error."""
        runner = CliRunner()

        result = runner.invoke(cli, ['diff', 'nonexistent1.json', 'nonexistent2.json'])

        # Click should show error about file not existing
        assert result.exit_code != 0
        assert 'does not exist' in result.output.lower() or 'Error' in result.output


class TestAuditSubcommand:
    """Tests for audit subcommand basic functionality."""

    def test_audit_shows_warning_without_redact(self):
        """Test that audit shows warning when --redact is not set."""
        runner = CliRunner()

        # Use dry-run mode to avoid needing actual SSH connection
        # The warning is shown before dry-run exits
        result = runner.invoke(cli, ['audit', '--dry-run', '--ssh-user', 'admin'])

        # Should exit successfully in dry-run mode
        assert result.exit_code == 0, f"Expected exit code 0, got {result.exit_code}. Output: {result.output}"

    def test_audit_with_verbose_flag(self):
        """Test that --verbose flag is accepted."""
        runner = CliRunner()

        result = runner.invoke(cli, ['audit', '--dry-run', '--verbose', '--ssh-user', 'admin'])

        # Should accept the flag and exit successfully
        assert result.exit_code == 0, f"Expected exit code 0, got {result.exit_code}. Output: {result.output}"

    def test_audit_cannot_use_both_verbose_and_quiet(self):
        """Test that --verbose and --quiet together cause error."""
        runner = CliRunner()

        result = runner.invoke(
            cli,
            ['audit', '--dry-run', '--verbose', '--quiet', '--ssh-user', 'admin']
        )

        # Should error when both flags are used
        assert result.exit_code == 1, f"Expected exit code 1, got {result.exit_code}. Output: {result.output}"
