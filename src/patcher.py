"""Patcher module for applying security fixes to RouterOS configuration.

This module provides safe, controlled application of security fixes with:
- Dry-run mode (preview changes)
- Confirmation for each change
- Rollback capability
- Backup before changes
"""

import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from src.ssh_handler import SSHHandler

logger = logging.getLogger(__name__)


@dataclass
class PatchAction:
    """Represents a single configuration change."""
    id: int
    description: str
    command: str
    rollback_command: Optional[str] = None
    confirmed: bool = False
    applied: bool = False
    error: Optional[str] = None


@dataclass
class PatchPlan:
    """Complete patching plan."""
    audit_id: Optional[int] = None
    router_ip: str = ""
    created_at: str = ""
    actions: List[PatchAction] = field(default_factory=list)
    total_actions: int = 0
    confirmed_actions: int = 0

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.total_actions = len(self.actions)
        self.confirmed_actions = sum(1 for a in self.actions if a.confirmed)


class Patcher:
    """
    Applies security fixes to RouterOS configuration.

    Usage:
        patcher = Patcher(ssh_handler)
        plan = patcher.create_plan(issues)
        patcher.dry_run(plan)  # Preview changes
        patcher.apply(plan)    # Apply confirmed changes
        patcher.rollback(plan) # Rollback if needed
    """

    def __init__(self, ssh_handler: SSHHandler):
        """
        Initialize patcher.

        Args:
            ssh_handler: SSH connection to router
        """
        self.ssh = ssh_handler
        self.applied_plans: List[PatchPlan] = []
        self.backup_file: Optional[str] = None

    def create_plan(self, issues: List[Dict]) -> PatchPlan:
        """
        Create patch plan from security issues.

        Args:
            issues: List of security issues with fix_commands

        Returns:
            PatchPlan with all proposed changes
        """
        actions = []
        action_id = 0

        for issue in issues:
            fix_commands = issue.get('fix_commands', [])
            if not fix_commands:
                continue

            # Filter out comments and empty lines
            commands = [c for c in fix_commands if c.strip() and not c.strip().startswith('#')]

            for cmd in commands:
                action_id += 1
                rollback = self._generate_rollback_command(cmd)

                action = PatchAction(
                    id=action_id,
                    description=issue.get('finding', 'Unknown issue'),
                    command=cmd.strip(),
                    rollback_command=rollback
                )
                actions.append(action)

        plan = PatchPlan(actions=actions)
        logger.info(f"Created patch plan with {len(actions)} actions")

        return plan

    def _generate_rollback_command(self, command: str) -> Optional[str]:
        """
        Generate rollback command for a given configuration change.

        This is a best-effort attempt to reverse common operations.
        """
        cmd = command.strip()

        # Handle 'add' commands - rollback is 'remove'
        if ' add ' in cmd:
            # Extract the path and find identifying parameters
            parts = cmd.split(' add ', 1)
            if len(parts) == 2:
                path = parts[0].strip()
                params = parts[1].strip()

                # Try to find name, comment, or other identifier
                import re
                name_match = re.search(r'name=(\S+)', params)
                if name_match:
                    return f"{path} remove [find where name={name_match.group(1)}]"

                # Try comment
                comment_match = re.search(r'comment="([^"]+)"', params)
                if comment_match:
                    return f"{path} remove [find where comment=\"{comment_match.group(1)}\"]"

                # Generic remove by finding the entry
                return f"{path} remove [find where {params.split('=')[0]}]"

        # Handle 'set' commands - would need original values for perfect rollback
        if ' set ' in cmd:
            # Can't perfectly rollback without original values
            # Mark as not rollbackable
            return None

        # Handle 'remove' commands - can't rollback
        if ' remove ' in cmd:
            return None

        # Handle 'disable'/'enable' - can toggle
        if ' disable ' in cmd:
            return cmd.replace(' disable ', ' enable ')
        if ' enable ' in cmd:
            return cmd.replace(' enable ', ' disable ')

        return None

    def dry_run(self, plan: PatchPlan) -> List[Dict]:
        """
        Preview changes without applying them.

        Args:
            plan: Patch plan to preview

        Returns:
            List of action descriptions
        """
        preview = []

        for action in plan.actions:
            preview.append({
                'id': action.id,
                'description': action.description,
                'command': action.command,
                'rollback': action.rollback_command,
                'rollback_available': action.rollback_command is not None
            })

        logger.info(f"Dry run: {len(preview)} actions planned")
        return preview

    def confirm_actions(self, plan: PatchPlan, action_ids: List[int]) -> int:
        """
        Confirm specific actions for application.

        Args:
            plan: Patch plan
            action_ids: List of action IDs to confirm

        Returns:
            Number of confirmed actions
        """
        confirmed = 0
        for action in plan.actions:
            if action.id in action_ids:
                action.confirmed = True
                confirmed += 1

        plan.confirmed_actions = confirmed
        logger.info(f"Confirmed {confirmed} actions")

        return confirmed

    def confirm_all(self, plan: PatchPlan) -> int:
        """Confirm all actions in plan."""
        return self.confirm_actions(plan, [a.id for a in plan.actions])

    def apply(self, plan: PatchPlan, create_backup: bool = True) -> Tuple[int, List[str]]:
        """
        Apply confirmed changes.

        Args:
            plan: Patch plan with confirmed actions
            create_backup: Whether to create backup before changes

        Returns:
            Tuple of (number of successful changes, list of errors)
        """
        if create_backup and not self.backup_file:
            self.backup_file = self._create_backup()

        applied = 0
        errors = []

        for action in plan.actions:
            if not action.confirmed:
                continue

            try:
                logger.info(f"Applying action {action.id}: {action.command[:50]}...")

                result = self.ssh.execute_command(action.command)

                if result.get('exit_status', 0) == 0:
                    action.applied = True
                    applied += 1
                    logger.info(f"Action {action.id} applied successfully")
                else:
                    error_msg = result.get('stderr', 'Unknown error')
                    action.error = error_msg
                    errors.append(f"Action {action.id}: {error_msg}")
                    logger.error(f"Action {action.id} failed: {error_msg}")

            except Exception as e:
                action.error = str(e)
                errors.append(f"Action {action.id}: {str(e)}")
                logger.error(f"Action {action.id} exception: {e}")

        if applied > 0:
            self.applied_plans.append(plan)

        logger.info(f"Applied {applied} changes, {len(errors)} errors")
        return applied, errors

    def rollback(self, plan: PatchPlan) -> Tuple[int, List[str]]:
        """
        Rollback applied changes.

        Args:
            plan: Patch plan to rollback

        Returns:
            Tuple of (number of rolled back changes, list of errors)
        """
        rolled_back = 0
        errors = []

        # Rollback in reverse order
        for action in reversed(plan.actions):
            if not action.applied:
                continue

            if not action.rollback_command:
                errors.append(f"Action {action.id}: No rollback command available")
                continue

            try:
                logger.info(f"Rolling back action {action.id}: {action.rollback_command[:50]}...")

                result = self.ssh.execute_command(action.rollback_command)

                if result.get('exit_status', 0) == 0:
                    action.applied = False
                    rolled_back += 1
                    logger.info(f"Action {action.id} rolled back successfully")
                else:
                    error_msg = result.get('stderr', 'Unknown error')
                    errors.append(f"Action {action.id}: {error_msg}")
                    logger.error(f"Action {action.id} rollback failed: {error_msg}")

            except Exception as e:
                errors.append(f"Action {action.id}: {str(e)}")
                logger.error(f"Action {action.id} rollback exception: {e}")

        logger.info(f"Rolled back {rolled_back} changes, {len(errors)} errors")
        return rolled_back, errors

    def restore_from_backup(self) -> bool:
        """
        Restore configuration from backup.

        Returns:
            True if restore successful
        """
        if not self.backup_file:
            logger.error("No backup file available")
            return False

        try:
            # Load backup
            load_cmd = f"/system backup load name={self.backup_file}"
            result = self.ssh.execute_command(load_cmd)

            if result.get('exit_status', 0) == 0:
                logger.info(f"Configuration restored from backup {self.backup_file}")
                return True
            else:
                logger.error(f"Backup restore failed: {result.get('stderr', 'Unknown error')}")
                return False

        except Exception as e:
            logger.error(f"Backup restore exception: {e}")
            return False

    def _create_backup(self) -> Optional[str]:
        """Create configuration backup."""
        try:
            backup_name = f"pre_patch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Create backup
            backup_cmd = f"/system backup save name={backup_name}"
            result = self.ssh.execute_command(backup_cmd)

            if result.get('exit_status', 0) == 0:
                self.backup_file = backup_name
                logger.info(f"Backup created: {backup_name}")
                return backup_name
            else:
                logger.error(f"Backup failed: {result.get('stderr', 'Unknown error')}")
                return None

        except Exception as e:
            logger.error(f"Backup exception: {e}")
            return None

    def get_status(self, plan: PatchPlan) -> Dict:
        """Get patching status for plan."""
        return {
            'total_actions': plan.total_actions,
            'confirmed_actions': plan.confirmed_actions,
            'applied_actions': sum(1 for a in plan.actions if a.applied),
            'failed_actions': sum(1 for a in plan.actions if a.error),
            'backup_available': self.backup_file is not None,
            'backup_file': self.backup_file
        }


def create_patch_plan(issues: List[Dict], ssh_handler: SSHHandler) -> PatchPlan:
    """
    Convenience function to create patch plan.

    Args:
        issues: List of security issues
        ssh_handler: SSH connection

    Returns:
        PatchPlan ready for review
    """
    patcher = Patcher(ssh_handler)
    return patcher.create_plan(issues)
