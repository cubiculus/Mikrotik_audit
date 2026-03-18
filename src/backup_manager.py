"""Backup manager for MikroTik RouterOS."""

import logging
from pathlib import Path
from typing import Optional

from colorama import Fore, Style
from src.config import BackupResult
from src.ssh_handler import SSHHandler

logger = logging.getLogger(__name__)


class BackupManager:
    """Manages system backup operations on MikroTik routers."""

    def __init__(self, ssh_handler: SSHHandler):
        """Initialize backup manager."""
        self.ssh = ssh_handler
        self._permission_denied = False

    def perform_backup(
        self,
        output_dir: Optional[Path] = None,
        timestamp: Optional[str] = None
    ) -> BackupResult:
        """
        Perform system backup, download it, and clean up from router.

        This method gracefully handles permission errors - if the user
        doesn't have write permissions, backup will be skipped with a warning.

        Args:
            output_dir: Directory to save backup (optional)
            timestamp: Timestamp for backup filename (optional)

        Returns:
            BackupResult with status and file information
        """
        import time

        backup_timestamp = timestamp or time.strftime("%Y%m%d_%H%M%S")
        backup_result = BackupResult(
            status="skipped",
            timestamp=backup_timestamp,
            file_name=None,
            error_message="Backup skipped - not required"
        )

        try:
            logger.info(f"{Fore.CYAN}  Creating system backup...{Style.RESET_ALL}")

            # Create backup (RouterOS v7 syntax: /system/backup/save)
            # Using dont-encrypt=yes to avoid encryption issues
            # Try without file-path first (uses default location)
            exit_status, output, stderr = self.ssh.execute_command(
                f"/system/backup/save name=audit_backup_{backup_timestamp} dont-encrypt=yes"
            )

            # Log raw output for debugging
            logger.debug(f"Backup command result: exit_status={exit_status}, output='{output[:200] if output else 'empty'}', stderr='{stderr[:200] if stderr else 'empty'}'")

            # If exit_status is 0 but output contains error text, treat as error
            if exit_status == 0 and output:
                output_lower = output.lower()
                if 'error' in output_lower or 'failed' in output_lower or 'cannot' in output_lower:
                    exit_status = 1
                    stderr = output

            # Check for permission denied or other errors
            if exit_status != 0:
                error_msg = stderr or output

                # Check for common permission errors
                permission_errors = [
                    "permission denied",
                    "insufficient privileges",
                    "no write permission",
                    "access denied",
                    "failure: no such item or access denied",
                    "no such user group",
                    "can not do that",
                    "not enough permissions",  # RouterOS specific error message
                ]

                if any(err in error_msg.lower() for err in permission_errors):
                    self._permission_denied = True
                    backup_result.status = "skipped"
                    backup_result.error_message = (
                        "Insufficient permissions: backup requires 'write' privileges. "
                        "Use a user with 'write' or 'full' access level."
                    )
                    logger.warning(
                        f"{Fore.YELLOW}  ⚠ Backup skipped: User does not have write permissions{Style.RESET_ALL}"
                    )
                    logger.warning(
                        f"{Fore.YELLOW}  (Use a user with 'write' or 'full' privileges to enable backups){Style.RESET_ALL}"
                    )
                else:
                    backup_result.status = "failed"
                    backup_result.error_message = f"Backup command failed: {error_msg[:200]}"
                    logger.error(f"Backup failed: {backup_result.error_message}")

                return backup_result

            # RouterOS v6/v7 doesn't output any success message - exit_status=0 indicates success
            # Verify backup was created by checking if file exists
            backup_filename = f"audit_backup_{backup_timestamp}.backup"
            file_size = self._get_file_size(backup_filename)

            if file_size is not None and file_size > 0:
                # Backup created successfully (file exists with non-zero size)
                backup_result.status = "success"
                backup_result.error_message = None
                backup_result.file_size = file_size

                logger.info(f"{Fore.GREEN}  ✓ Backup created successfully ({file_size} bytes){Style.RESET_ALL}")
                backup_result.file_name = backup_filename

                # Download backup file
                if output_dir:
                    self._download_backup(backup_filename, output_dir, backup_result)

                # Clean up from router (also handle permission errors)
                self._cleanup_backup(backup_filename)

            elif exit_status == 0:
                # Exit status is 0 but file not found - RouterOS v7 may store backups differently
                # or there may be no storage available. Treat as skipped rather than failed.
                backup_result.status = "skipped"
                backup_result.error_message = (
                    "RouterOS v7 does not support automatic backup download. "
                    "Backup may have been created but cannot be verified or downloaded automatically. "
                    "Manual backup via WinBox or Terminal is recommended."
                )
                backup_result.file_name = backup_filename
                logger.warning(
                    f"{Fore.YELLOW}  ⚠ Backup status unknown: RouterOS v7 limitation{Style.RESET_ALL}"
                )
                logger.warning(
                    f"{Fore.YELLOW}  (Manual backup recommended via WinBox: Files → Backup){Style.RESET_ALL}"
                )

            else:
                # exit_status != 0 and file not found - definite failure
                error_msg = stderr or output or "Backup command returned unexpected response"

                # Check for error keywords in output
                error_keywords = ["error", "failed", "cannot", "permission", "denied"]
                if any(kw in error_msg.lower() for kw in error_keywords):
                    backup_result.error_message = f"Backup failed: {error_msg[:200]}"
                else:
                    backup_result.error_message = f"Unexpected output: {error_msg[:100]}"

                backup_result.status = "failed"
                logger.error(f"{Fore.RED}  ✗ Backup failed: {backup_result.error_message}{Style.RESET_ALL}")

        except Exception as e:
            backup_result.status = "failed"
            backup_result.error_message = str(e)
            logger.error(f"Backup operation failed: {e}")

        return backup_result

    def _get_file_size(self, filename: str) -> Optional[int]:
        """Get file size from router."""
        _, file_output, _ = self.ssh.execute_command(
            f'/file print detail where name="{filename}"'
        )

        for line in file_output.split('\n'):
            if 'size:' in line.lower():
                try:
                    size_str = line.split(':', 1)[1].strip().split()[0]
                    return int(size_str)
                except (ValueError, IndexError):
                    pass
        return None

    def _download_backup(
        self,
        filename: str,
        output_dir: Path,
        backup_result: BackupResult
    ):
        """Download backup file from router."""
        logger.info(f"{Fore.CYAN}  Downloading backup file to {output_dir}...{Style.RESET_ALL}")

        try:
            with self.ssh.connection_pool.get_connection() as ssh_client:
                # Check if SFTP is supported
                transport = ssh_client.get_transport()
                if not transport:
                    raise Exception("SSH transport not available")

                # Verify SFTP subsystem is available
                if not transport.is_active():
                    raise Exception("SSH transport is not active")

                # Open SFTP session
                sftp = None
                try:
                    sftp = ssh_client.open_sftp()
                    logger.debug("SFTP session established successfully")
                except Exception as sftp_error:
                    logger.error(f"SFTP not supported or failed: {sftp_error}")
                    raise Exception(
                        f"SFTP is not available on the router. "
                        f"Please ensure SSH service is enabled and supports SFTP. "
                        f"Error: {sftp_error}"
                    )

                # Find backup file (case-insensitive)
                try:
                    remote_files = sftp.listdir('.')
                    matching_files = [f for f in remote_files if filename.lower() in f.lower()]
                    if matching_files:
                        filename = matching_files[0]
                        logger.info(f"Matching files: {matching_files}")
                except Exception as list_err:
                    logger.warning(f"Could not list remote files: {list_err}")

                remote_path = filename
                local_path = output_dir / filename

                # Create local directory if needed
                output_dir.mkdir(parents=True, exist_ok=True)

                # Download file
                sftp.get(remote_path, str(local_path))
                sftp.close()

                # Verify file exists
                if local_path.exists():
                    logger.info(f"{Fore.GREEN}  ✓ Backup downloaded successfully{Style.RESET_ALL}: {local_path.name}")
                    backup_result.local_path = str(local_path)
                    backup_result.file_size = local_path.stat().st_size
                else:
                    logger.warning(f"Download completed but file not found at: {local_path}")
                    backup_result.download_error = "Download failed - file not found after transfer"

        except Exception as e:
            logger.warning(f"Failed to download backup file: {e}")
            backup_result.download_error = str(e)

    def _cleanup_backup(self, filename: str):
        """Delete backup file from router. Handles permission errors gracefully."""
        logger.info("Cleaning up backup file from router...")

        # Используем безопасный синтаксис с экранированием имени
        exit_status, output, stderr = self.ssh.execute_command(f'/file remove [find name="{filename}"]')

        if exit_status == 0:
            logger.info(f"✓ Backup file removed from router: {filename}")
        else:
            # Check if it's a permission error
            error_msg = stderr or output
            permission_errors = [
                "permission denied",
                "insufficient privileges",
                "no write permission",
                "access denied"
            ]

            if any(err in error_msg.lower() for err in permission_errors):
                logger.debug(f"Cleanup skipped (permission denied): {filename}")
            else:
                logger.warning(f"✗ Failed to remove backup file from router: {filename} - {error_msg}")
