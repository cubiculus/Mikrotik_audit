"""Tests for patcher module."""

from unittest.mock import patch
from src.patcher import Patcher, PatchPlan, PatchAction, create_patch_plan


class MockSSHHandler:
    """Mock SSH handler for testing."""

    def __init__(self, success=True):
        self.success = success
        self.commands_executed = []

    def execute_command(self, command):
        self.commands_executed.append(command)
        if self.success:
            return {'exit_status': 0, 'stdout': '', 'stderr': ''}
        else:
            return {'exit_status': 1, 'stdout': '', 'stderr': 'Command failed'}


class TestPatchAction:
    """Tests for PatchAction dataclass."""

    def test_create_action(self):
        """Test creating PatchAction."""
        action = PatchAction(
            id=1,
            description="Test issue",
            command="/ip firewall filter add chain=input action=accept"
        )

        assert action.id == 1
        assert action.confirmed is False
        assert action.applied is False
        assert action.error is None

    def test_create_action_with_rollback(self):
        """Test creating PatchAction with rollback."""
        action = PatchAction(
            id=1,
            description="Test",
            command="/command",
            rollback_command="/rollback"
        )

        assert action.rollback_command == "/rollback"


class TestPatchPlan:
    """Tests for PatchPlan dataclass."""

    def test_create_plan(self):
        """Test creating PatchPlan."""
        plan = PatchPlan(
            router_ip="192.168.88.1",
            actions=[PatchAction(id=1, description="Test", command="/cmd")]
        )

        assert plan.router_ip == "192.168.88.1"
        assert plan.total_actions == 1
        assert plan.confirmed_actions == 0
        assert plan.created_at is not None

    def test_plan_auto_counts(self):
        """Test that plan auto-counts actions."""
        actions = [
            PatchAction(id=1, description="Test", command="/cmd", confirmed=True),
            PatchAction(id=2, description="Test", command="/cmd", confirmed=False),
            PatchAction(id=3, description="Test", command="/cmd", confirmed=True),
        ]
        plan = PatchPlan(actions=actions)

        assert plan.total_actions == 3
        # confirmed_actions is calculated in __post_init__
        assert plan.confirmed_actions == 2


class TestPatcherCreatePlan:
    """Tests for Patcher.create_plan."""

    def test_create_plan_from_issues(self):
        """Test creating plan from security issues."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        issues = [
            {
                'finding': 'Test issue 1',
                'fix_commands': [
                    '# Comment',
                    '/command1',
                    '',
                    '/command2'
                ]
            },
            {
                'finding': 'Test issue 2',
                'fix_commands': ['/command3']
            }
        ]

        plan = patcher.create_plan(issues)

        assert plan.total_actions == 3
        assert plan.actions[0].command == '/command1'
        assert plan.actions[1].command == '/command2'
        assert plan.actions[2].command == '/command3'

    def test_create_plan_empty_issues(self):
        """Test creating plan from empty issues."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        plan = patcher.create_plan([])

        assert plan.total_actions == 0

    def test_create_plan_issues_without_fixes(self):
        """Test creating plan from issues without fix_commands."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        issues = [
            {'finding': 'Issue without fixes'},
            {'finding': 'Issue with empty fixes', 'fix_commands': []}
        ]

        plan = patcher.create_plan(issues)

        assert plan.total_actions == 0


class TestPatcherRollbackGeneration:
    """Tests for rollback command generation."""

    def test_rollback_add_command_with_name(self):
        """Test rollback generation for add command with name."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        cmd = '/ip firewall filter add chain=input action=accept name=myrule'
        rollback = patcher._generate_rollback_command(cmd)

        assert rollback is not None
        assert 'remove' in rollback
        assert 'name=myrule' in rollback

    def test_rollback_add_command_with_comment(self):
        """Test rollback generation for add command with comment."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        cmd = '/ip firewall filter add chain=input action=accept comment="Test rule"'
        rollback = patcher._generate_rollback_command(cmd)

        assert rollback is not None
        assert 'remove' in rollback

    def test_rollback_set_command(self):
        """Test rollback generation for set command."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        cmd = '/ip ssh set strong-crypto=yes'
        rollback = patcher._generate_rollback_command(cmd)

        # Set commands can't be perfectly rolled back without original values
        assert rollback is None

    def test_rollback_remove_command(self):
        """Test rollback generation for remove command."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        cmd = '/ip firewall filter remove numbers=0'
        rollback = patcher._generate_rollback_command(cmd)

        # Remove commands can't be rolled back
        assert rollback is None

    def test_rollback_disable_command(self):
        """Test rollback generation for disable command."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        cmd = '/interface disable ether1'
        rollback = patcher._generate_rollback_command(cmd)

        assert rollback == '/interface enable ether1'

    def test_rollback_enable_command(self):
        """Test rollback generation for enable command."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        cmd = '/interface enable ether1'
        rollback = patcher._generate_rollback_command(cmd)

        assert rollback == '/interface disable ether1'


class TestPatcherDryRun:
    """Tests for Patcher.dry_run."""

    def test_dry_run_returns_preview(self):
        """Test dry run returns action preview."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        issues = [
            {
                'finding': 'Test issue',
                'fix_commands': ['/command1', '/command2']
            }
        ]

        plan = patcher.create_plan(issues)
        preview = patcher.dry_run(plan)

        assert len(preview) == 2
        assert preview[0]['command'] == '/command1'
        assert preview[0]['description'] == 'Test issue'

    def test_dry_run_shows_rollback(self):
        """Test dry run includes rollback information."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        issues = [
            {
                'finding': 'Test',
                'fix_commands': ['/interface disable ether1']
            }
        ]

        plan = patcher.create_plan(issues)
        preview = patcher.dry_run(plan)

        assert preview[0]['rollback'] == '/interface enable ether1'
        assert preview[0]['rollback_available'] is True


class TestPatcherConfirm:
    """Tests for Patcher.confirm_actions."""

    def test_confirm_specific_actions(self):
        """Test confirming specific actions."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        issues = [
            {'finding': 'Issue 1', 'fix_commands': ['/cmd1']},
            {'finding': 'Issue 2', 'fix_commands': ['/cmd2']}
        ]

        plan = patcher.create_plan(issues)
        confirmed = patcher.confirm_actions(plan, [1])

        assert confirmed == 1
        assert plan.actions[0].confirmed is True
        assert plan.actions[1].confirmed is False

    def test_confirm_all_actions(self):
        """Test confirming all actions."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        issues = [
            {'finding': 'Issue 1', 'fix_commands': ['/cmd1']},
            {'finding': 'Issue 2', 'fix_commands': ['/cmd2']}
        ]

        plan = patcher.create_plan(issues)
        confirmed = patcher.confirm_all(plan)

        assert confirmed == 2
        assert all(a.confirmed for a in plan.actions)


class TestPatcherApply:
    """Tests for Patcher.apply."""

    def test_apply_confirmed_actions(self):
        """Test applying confirmed actions."""
        ssh = MockSSHHandler(success=True)
        patcher = Patcher(ssh)

        issues = [
            {'finding': 'Test', 'fix_commands': ['/cmd1', '/cmd2']}
        ]

        plan = patcher.create_plan(issues)
        patcher.confirm_all(plan)

        applied, errors = patcher.apply(plan)

        assert applied == 2
        assert len(errors) == 0
        # Backup command + 2 fix commands
        assert len(ssh.commands_executed) == 3
        assert '/cmd1' in ssh.commands_executed
        assert '/cmd2' in ssh.commands_executed

    def test_apply_only_confirmed(self):
        """Test that only confirmed actions are applied."""
        ssh = MockSSHHandler(success=True)
        patcher = Patcher(ssh)

        issues = [
            {'finding': 'Issue 1', 'fix_commands': ['/cmd1']},
            {'finding': 'Issue 2', 'fix_commands': ['/cmd2']}
        ]

        plan = patcher.create_plan(issues)
        patcher.confirm_actions(plan, [1])  # Only confirm first

        applied, errors = patcher.apply(plan)

        assert applied == 1
        # Backup + confirmed command
        assert '/cmd1' in ssh.commands_executed
        assert '/cmd2' not in ssh.commands_executed

    def test_apply_with_errors(self):
        """Test applying with some failures."""
        ssh = MockSSHHandler(success=False)
        patcher = Patcher(ssh)

        issues = [
            {'finding': 'Test', 'fix_commands': ['/cmd1', '/cmd2']}
        ]

        plan = patcher.create_plan(issues)
        patcher.confirm_all(plan)

        applied, errors = patcher.apply(plan)

        assert applied == 0
        assert len(errors) == 2

    def test_apply_creates_backup(self):
        """Test that apply creates backup."""
        ssh = MockSSHHandler(success=True)
        patcher = Patcher(ssh)

        issues = [{'finding': 'Test', 'fix_commands': ['/cmd']}]
        plan = patcher.create_plan(issues)
        patcher.confirm_all(plan)

        # Mock the backup creation
        with patch.object(patcher, '_create_backup', return_value='test_backup'):
            patcher.apply(plan)

        assert patcher.backup_file == 'test_backup'


class TestPatcherRollback:
    """Tests for Patcher.rollback."""

    def test_rollback_applied_actions(self):
        """Test rolling back applied actions."""
        ssh = MockSSHHandler(success=True)
        patcher = Patcher(ssh)

        issues = [
            {'finding': 'Test', 'fix_commands': ['/interface disable ether1']}
        ]

        plan = patcher.create_plan(issues)
        patcher.confirm_all(plan)

        # Manually mark as applied
        plan.actions[0].applied = True

        rolled_back, errors = patcher.rollback(plan)

        assert rolled_back == 1
        assert len(errors) == 0
        assert '/interface enable ether1' in ssh.commands_executed

    def test_rollback_skips_unapplied(self):
        """Test that rollback skips unapplied actions."""
        ssh = MockSSHHandler(success=True)
        patcher = Patcher(ssh)

        plan = PatchPlan(actions=[
            PatchAction(id=1, description="Test", command="/cmd", applied=False)
        ])

        rolled_back, errors = patcher.rollback(plan)

        assert rolled_back == 0
        assert len(ssh.commands_executed) == 0

    def test_rollback_skips_no_rollback_command(self):
        """Test that rollback skips actions without rollback command."""
        ssh = MockSSHHandler(success=True)
        patcher = Patcher(ssh)

        plan = PatchPlan(actions=[
            PatchAction(id=1, description="Test", command="/cmd",
                       applied=True, rollback_command=None)
        ])

        rolled_back, errors = patcher.rollback(plan)

        assert rolled_back == 0
        assert len(errors) == 1
        assert 'No rollback command' in errors[0]


class TestPatcherStatus:
    """Tests for Patcher.get_status."""

    def test_get_status(self):
        """Test getting patcher status."""
        ssh = MockSSHHandler()
        patcher = Patcher(ssh)

        issues = [{'finding': 'Test', 'fix_commands': ['/cmd1', '/cmd2']}]
        plan = patcher.create_plan(issues)
        patcher.confirm_actions(plan, [1])

        status = patcher.get_status(plan)

        assert status['total_actions'] == 2
        assert status['confirmed_actions'] == 1
        assert status['applied_actions'] == 0
        assert 'backup_available' in status


class TestConvenienceFunction:
    """Tests for create_patch_plan convenience function."""

    def test_create_patch_plan(self):
        """Test create_patch_plan function."""
        ssh = MockSSHHandler()

        issues = [{'finding': 'Test', 'fix_commands': ['/cmd']}]
        plan = create_patch_plan(issues, ssh)

        assert isinstance(plan, PatchPlan)
        assert plan.total_actions == 1
