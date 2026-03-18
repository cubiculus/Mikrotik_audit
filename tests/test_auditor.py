"""Tests for auditor module."""

from unittest.mock import patch, MagicMock

from src.config import RouterConfig, AuditConfig, AuditLevel, CommandResult
from src.auditor import MikroTikAuditor
from src.commands import (
    AUDIT_COMMANDS_BASIC,
    AUDIT_COMMANDS_STANDARD,
    AUDIT_COMMANDS_COMPREHENSIVE,
)


class TestGetAuditCommandsByLevel:
    """Tests for get_audit_commands method based on audit level."""

    def test_basic_audit_level_returns_basic_commands(self):
        """Test that BASIC audit level returns AUDIT_COMMANDS_BASIC."""
        config = AuditConfig(audit_level=AuditLevel.BASIC)
        auditor = MikroTikAuditor(config)

        commands = auditor.get_audit_commands()

        assert commands == AUDIT_COMMANDS_BASIC
        assert len(commands) > 0
        # Verify basic commands contain expected items
        assert "/system identity print" in commands
        assert "/system resource print" in commands

    def test_standard_audit_level_returns_standard_commands(self):
        """Test that STANDARD audit level returns AUDIT_COMMANDS_STANDARD."""
        config = AuditConfig(audit_level=AuditLevel.STANDARD)
        auditor = MikroTikAuditor(config)

        commands = auditor.get_audit_commands()

        assert commands == AUDIT_COMMANDS_STANDARD
        assert len(commands) > len(AUDIT_COMMANDS_BASIC)
        # Verify standard commands contain expected items
        assert "/system identity print" in commands
        assert "/ip firewall filter print detail without-paging" in commands
        assert "/export hide-sensitive" in commands

    def test_comprehensive_audit_level_returns_comprehensive_commands(self):
        """Test that COMPREHENSIVE audit level returns AUDIT_COMMANDS_COMPREHENSIVE."""
        config = AuditConfig(audit_level=AuditLevel.COMPREHENSIVE)
        auditor = MikroTikAuditor(config)

        commands = auditor.get_audit_commands()

        assert commands == AUDIT_COMMANDS_COMPREHENSIVE
        assert len(commands) > len(AUDIT_COMMANDS_STANDARD)
        # Verify comprehensive commands contain expected items
        assert "/system identity print" in commands
        assert "/routing bgp instance print detail" in commands
        assert "/ipv6 address print detail" in commands

    def test_audit_commands_are_unique_lists(self):
        """Test that each audit level has a unique set of commands."""
        assert AUDIT_COMMANDS_BASIC != AUDIT_COMMANDS_STANDARD
        assert AUDIT_COMMANDS_STANDARD != AUDIT_COMMANDS_COMPREHENSIVE
        assert AUDIT_COMMANDS_BASIC != AUDIT_COMMANDS_COMPREHENSIVE

    def test_basic_commands_subset_of_comprehensive(self):
        """Test that basic commands are mostly included in comprehensive."""
        # Most basic commands should be in comprehensive
        basic_set = set(AUDIT_COMMANDS_BASIC)
        comprehensive_set = set(AUDIT_COMMANDS_COMPREHENSIVE)

        # At least the core commands should overlap
        common_commands = basic_set.intersection(comprehensive_set)
        assert len(common_commands) >= 3  # identity, resource, clock should be common


class TestExecuteCommandRetryLogic:
    """Tests for execute_command retry behavior."""

    def _create_auditor(self):
        """Helper to create auditor with test config."""
        config = AuditConfig(
            router=RouterConfig(max_retries=3),
            audit_level=AuditLevel.BASIC
        )
        return MikroTikAuditor(config)

    @patch('src.auditor.SSHHandler')
    def test_execute_command_retry_on_failure_then_success(self, mock_ssh_handler):
        """Test command fails 2 times, succeeds on 3rd attempt."""
        auditor = self._create_auditor()

        # Mock SSH connection
        mock_ssh = MagicMock()
        auditor.ssh = mock_ssh

        # Configure side_effect: 2 failures, then success
        mock_ssh.execute_command.side_effect = [
            (1, "", "Error attempt 1"),  # Attempt 1: failure
            (1, "", "Error attempt 2"),  # Attempt 2: failure
            (0, "Success output", ""),   # Attempt 3: success
        ]

        result = auditor.execute_command(index=1, command="/test command")

        # Verify result is successful
        assert result.has_error is False
        assert result.exit_status == 0
        assert result.stdout == "Success output"
        assert result.attempt == 3  # Succeeded on 3rd attempt

        # Verify execute_command was called 3 times
        assert mock_ssh.execute_command.call_count == 3

    @patch('src.auditor.SSHHandler')
    def test_execute_command_all_retries_fail(self, mock_ssh_handler):
        """Test command fails on all retry attempts."""
        auditor = self._create_auditor()

        mock_ssh = MagicMock()
        auditor.ssh = mock_ssh

        # All 3 attempts fail
        mock_ssh.execute_command.side_effect = [
            (1, "", "Error 1"),
            (1, "", "Error 2"),
            (1, "", "Error 3"),
        ]

        result = auditor.execute_command(index=1, command="/test command")

        # Verify result indicates failure
        assert result.has_error is True
        assert result.exit_status == 1
        assert result.attempt == 3  # All 3 attempts used

        assert mock_ssh.execute_command.call_count == 3

    @patch('src.auditor.SSHHandler')
    def test_execute_command_exception_retry(self, mock_ssh_handler):
        """Test command raises exception, then succeeds on retry."""
        auditor = self._create_auditor()

        mock_ssh = MagicMock()
        auditor.ssh = mock_ssh

        # First call raises exception, second succeeds
        mock_ssh.execute_command.side_effect = [
            Exception("Connection timeout"),  # Attempt 1: exception
            (0, "Success after exception", ""),  # Attempt 2: success
        ]

        result = auditor.execute_command(index=1, command="/test command")

        assert result.has_error is False
        assert result.stdout == "Success after exception"
        assert result.attempt == 2

        assert mock_ssh.execute_command.call_count == 2

    @patch('src.auditor.SSHHandler')
    def test_execute_command_exception_all_retries(self, mock_ssh_handler):
        """Test command raises exception on all retries."""
        auditor = self._create_auditor()

        mock_ssh = MagicMock()
        auditor.ssh = mock_ssh

        # All attempts raise exceptions
        mock_ssh.execute_command.side_effect = [
            Exception("Error 1"),
            Exception("Error 2"),
            Exception("Error 3"),
        ]

        result = auditor.execute_command(index=1, command="/test command")

        assert result.has_error is True
        assert result.error_type == "Exception"
        assert result.attempt == 3


class TestExecuteCommandNoRetryOnSuccess:
    """Tests that successful commands don't perform unnecessary retries."""

    def _create_auditor(self):
        """Helper to create auditor with test config."""
        config = AuditConfig(
            router=RouterConfig(max_retries=5),  # High retry count to verify no extra calls
            audit_level=AuditLevel.BASIC
        )
        return MikroTikAuditor(config)

    @patch('src.auditor.SSHHandler')
    def test_execute_command_success_no_extra_attempts(self, mock_ssh_handler):
        """Test successful command executes only once, no retries."""
        auditor = self._create_auditor()

        mock_ssh = MagicMock()
        auditor.ssh = mock_ssh

        # Single successful execution
        mock_ssh.execute_command.return_value = (0, "Success", "")

        result = auditor.execute_command(index=1, command="/test command")

        # Verify single execution
        assert mock_ssh.execute_command.call_count == 1
        assert result.attempt == 1
        assert result.has_error is False
        assert result.exit_status == 0

    @patch('src.auditor.SSHHandler')
    def test_execute_command_success_first_attempt(self, mock_ssh_handler):
        """Test that success on first attempt prevents further retries."""
        auditor = self._create_auditor()

        mock_ssh = MagicMock()
        auditor.ssh = mock_ssh

        mock_ssh.execute_command.return_value = (0, "Immediate success", "")

        result = auditor.execute_command(index=5, command="/system identity print")

        # Only one call should be made
        mock_ssh.execute_command.assert_called_once_with("/system identity print")
        assert result.attempt == 1
        assert result.duration >= 0


class TestGroupCommandsByPriority:
    """Tests for _group_commands_by_priority method."""

    def _create_auditor(self):
        """Helper to create auditor with test config."""
        config = AuditConfig(audit_level=AuditLevel.STANDARD)
        return MikroTikAuditor(config)

    def test_group_commands_fast_commands(self):
        """Test fast commands are correctly grouped."""
        auditor = self._create_auditor()

        commands = [
            '/system identity print',
            '/system resource print',
            '/system clock print',
            '/interface print stats',
            '/some other command',
        ]

        grouped = auditor._group_commands_by_priority(commands)

        assert len(grouped['fast']) == 4
        assert '/system identity print' in grouped['fast']
        assert '/system resource print' in grouped['fast']
        assert '/system clock print' in grouped['fast']
        assert '/interface print stats' in grouped['fast']
        assert '/some other command' not in grouped['fast']

    def test_group_commands_heavy_commands(self):
        """Test heavy commands are correctly grouped."""
        auditor = self._create_auditor()

        commands = [
            '/tool sniffer quick',
            '/ip firewall filter print detail',
            '/ip firewall nat print detail',
            '/system identity print',  # Not heavy
        ]

        grouped = auditor._group_commands_by_priority(commands)

        assert len(grouped['heavy']) == 3
        assert '/tool sniffer quick' in grouped['heavy']
        assert '/ip firewall filter print detail' in grouped['heavy']
        assert '/ip firewall nat print detail' in grouped['heavy']

    def test_group_commands_dependent_commands(self):
        """Test dependent commands are correctly grouped."""
        auditor = self._create_auditor()

        commands = [
            '/export hide-sensitive',
            '/system identity print',  # Not dependent
        ]

        grouped = auditor._group_commands_by_priority(commands)

        assert len(grouped['dependent']) == 1
        assert '/export hide-sensitive' in grouped['dependent']

    def test_group_commands_normal_commands(self):
        """Test normal commands (not fast/heavy/dependent) are grouped."""
        auditor = self._create_auditor()

        commands = [
            '/system identity print',  # Fast
            '/ip route print detail',  # Normal
            '/user print detail',      # Normal
            '/tool sniffer quick',     # Heavy
        ]

        grouped = auditor._group_commands_by_priority(commands)

        assert len(grouped['normal']) == 2
        assert '/ip route print detail' in grouped['normal']
        assert '/user print detail' in grouped['normal']
        assert '/system identity print' not in grouped['normal']
        assert '/tool sniffer quick' not in grouped['normal']

    def test_group_commands_complete_categorization(self):
        """Test all commands are categorized into exactly one group."""
        auditor = self._create_auditor()

        commands = [
            '/system identity print',      # Fast
            '/ip firewall filter print detail',  # Heavy
            '/export hide-sensitive',      # Dependent
            '/ip route print detail',      # Normal
            '/user print detail',          # Normal
        ]

        grouped = auditor._group_commands_by_priority(commands)

        # All commands should be in exactly one group
        all_grouped = (
            grouped['fast'] +
            grouped['heavy'] +
            grouped['dependent'] +
            grouped['normal']
        )

        assert len(all_grouped) == len(commands)
        assert set(all_grouped) == set(commands)

    def test_group_commands_empty_input(self):
        """Test grouping with empty command list."""
        auditor = self._create_auditor()

        grouped = auditor._group_commands_by_priority([])

        assert grouped['fast'] == []
        assert grouped['heavy'] == []
        assert grouped['dependent'] == []
        assert grouped['normal'] == []

    def test_group_commands_with_standard_audit_commands(self):
        """Test grouping with actual STANDARD audit commands."""
        auditor = MikroTikAuditor(AuditConfig(audit_level=AuditLevel.STANDARD))

        commands = auditor.get_audit_commands()
        grouped = auditor._group_commands_by_priority(commands)

        # Verify groups are non-empty where expected
        assert len(grouped['fast']) >= 3  # identity, resource, clock
        assert len(grouped['heavy']) >= 2  # firewall filter, nat
        assert len(grouped['dependent']) == 1  # export
        assert len(grouped['normal']) > 0  # many other commands

        # Verify no duplicates across groups
        all_commands = (
            grouped['fast'] +
            grouped['heavy'] +
            grouped['dependent'] +
            grouped['normal']
        )
        assert len(all_commands) == len(set(all_commands)) == len(commands)


class TestGetOptimalWorkers:
    """Tests for _get_optimal_workers method."""

    def _create_auditor(self, max_workers=0, audit_level=AuditLevel.STANDARD):
        """Helper to create auditor with specific config."""
        config = AuditConfig(
            max_workers=max_workers,
            audit_level=audit_level
        )
        return MikroTikAuditor(config)

    def test_get_optimal_workers_small_command_count(self):
        """Test worker calculation for small command sets."""
        auditor = self._create_auditor(max_workers=0, audit_level=AuditLevel.BASIC)

        workers = auditor._get_optimal_workers()

        # For < 10 commands, should be min(3, command_count)
        assert workers <= 3
        assert workers >= 1

    def test_get_optimal_workers_medium_command_count(self):
        """Test worker calculation for medium command sets."""
        auditor = self._create_auditor(max_workers=0, audit_level=AuditLevel.STANDARD)

        workers = auditor._get_optimal_workers()

        # For 10-50 commands, should be min(5, 4) = 4
        assert workers <= 5
        assert workers >= 4

    def test_get_optimal_workers_large_command_count(self):
        """Test worker calculation for large command sets."""
        auditor = self._create_auditor(max_workers=0, audit_level=AuditLevel.COMPREHENSIVE)

        workers = auditor._get_optimal_workers()

        # For > 50 commands, should be min(6, 5) = 5
        assert workers <= 6
        assert workers >= 4

    def test_get_optimal_workers_user_configured(self):
        """Test that user-configured max_workers is respected."""
        auditor = self._create_auditor(max_workers=8)

        workers = auditor._get_optimal_workers()

        assert workers == 8

    def test_get_optimal_workers_user_configured_zero(self):
        """Test that max_workers=0 triggers auto-calculation."""
        auditor = self._create_auditor(max_workers=0)

        workers = auditor._get_optimal_workers()

        # Should auto-calculate, not be 0
        assert workers > 0


class TestExecutePhase:
    """Tests for _execute_phase method."""

    def _create_auditor(self):
        """Helper to create auditor with test config."""
        config = AuditConfig(audit_level=AuditLevel.BASIC)
        return MikroTikAuditor(config)

    @patch('src.auditor.MikroTikAuditor._execute_command_group')
    @patch('src.auditor.MikroTikAuditor.execute_command')
    def test_execute_phase_all_four_phases(self, mock_execute_cmd, mock_execute_group):
        """Test all four phases are executed in order."""
        auditor = self._create_auditor()
        auditor.results = []

        # Mock execute_command for dependent phase
        mock_execute_cmd.return_value = CommandResult(
            index=1,
            command="/export hide-sensitive",
            exit_status=0,
            stdout="",
            stderr="",
            duration=0.1
        )

        grouped = {
            'fast': ['/system identity print'],
            'heavy': ['/tool sniffer quick'],
            'dependent': ['/export hide-sensitive'],
            'normal': ['/ip route print detail'],
        }

        auditor._execute_phase(grouped, total=4)

        # Verify all phases were called
        assert mock_execute_group.call_count == 3  # fast, heavy, normal
        assert mock_execute_cmd.call_count == 1  # dependent (sequential)

    @patch('src.auditor.MikroTikAuditor._execute_command_group')
    def test_execute_phase_empty_groups(self, mock_execute_group):
        """Test phase execution with empty groups."""
        auditor = self._create_auditor()
        auditor.results = []

        grouped = {
            'fast': [],
            'heavy': [],
            'dependent': [],
            'normal': [],
        }

        auditor._execute_phase(grouped, total=0)

        # No groups should be executed
        assert mock_execute_group.call_count == 0
