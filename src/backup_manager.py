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

            # RouterOS CLI syntax (space-separated, works on v6 and v7 via SSH).
            # No password = not encrypted backup by default on most versions.  # noqa: PII
            # dont-encrypt=yes is only needed on RouterOS 7.4+ where encryption
            # may be required by policy — tried as fallback below.
            exit_status, output, stderr = self.ssh.execute_command(
                f"/system backup save name=audit_backup_{backup_timestamp}"
            )

            logger.debug(
                f"Backup command exit status: {exit_status}"
            )

            # RouterOS 7.4+ may require dont-encrypt=yes when encryption policy
            # is set. Detect and retry once with the explicit flag.
            if exit_status != 0:
                error_text = (stderr or output or "").lower()
                needs_encrypt_flag = (
                    "encrypt" in error_text
                    or "password" in error_text
                    or "dont-encrypt" in error_text
                )
                if needs_encrypt_flag:
                    logger.info(
                        f"{Fore.YELLOW}  Retrying backup with dont-encrypt=yes "
                        f"(RouterOS 7.4+ policy){Style.RESET_ALL}"
                    )
                    exit_status, output, stderr = self.ssh.execute_command(
                        f"/system backup save name=audit_backup_{backup_timestamp} dont-encrypt=yes"
                    )
                    logger.debug(f"Retry backup command exit status: {exit_status}")

            # Check for permission denied or other errors
            if exit_status != 0:
                error_msg = stderr or output or ""

                permission_errors = [
                    "permission denied",
                    "insufficient privileges",
                    "no write permission",
                    "access denied",
                    "failure: no such item or access denied",
                    "no such user group",
                    "can not do that",
                    "not enough permissions",
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

            # exit_status == 0: RouterOS doesn't print a success message.
            # Wait a moment for the file to be written to disk
            import time
            time.sleep(1.5)  # RouterOS may take time to sync file to storage

            # Verify the file actually exists on the router (root directory only)
            backup_filename = f"audit_backup_{backup_timestamp}.backup"
            file_size = self._get_file_size(backup_filename)

            # Retry once if file not found (RouterOS file system sync delay)
            if file_size is None:
                logger.debug("Backup file not found immediately, retrying...")
                time.sleep(2.0)
                file_size = self._get_file_size(backup_filename)

            if file_size is not None and file_size > 0:
                # File confirmed on router — backup successful.
                backup_result.status = "success"
                backup_result.error_message = None
                backup_result.file_size = file_size
                backup_result.file_name = backup_filename

                logger.info(
                    f"{Fore.GREEN}  ✓ Backup created successfully ({file_size} bytes){Style.RESET_ALL}"
                )

                if output_dir:
                    self._download_backup(backup_filename, output_dir, backup_result)

                self._cleanup_backup(backup_filename)

            else:
                # exit_status=0 but file missing — command appeared to succeed
                # but no file was written (storage full, wrong path, etc.).
                backup_result.status = "failed"
                backup_result.file_name = backup_filename
                backup_result.error_message = (
                    f"Backup command returned exit_status=0 but file not found: {backup_filename}. "
                    "Possible causes: insufficient storage on router, or silent RouterOS error. "
                    "Check available space with '/disk print' and router logs."
                )
                logger.error(
                    f"{Fore.RED}  ✗ Backup failed: command succeeded but file not found{Style.RESET_ALL}"
                )

        except Exception as e:
            backup_result.status = "failed"
            backup_result.error_message = str(e)
            logger.error(f"Backup operation failed: {e}")

        return backup_result

    def _get_file_size(self, filename: str) -> Optional[int]:
        """Get file size from router. Only checks root directory files."""
        # RouterOS v7: /file print detail where name="..." doesn't work reliably
        # Use /file print where type="backup" and find by name instead
        _, file_output, _ = self.ssh.execute_command(
            '/file print where type="backup"'
        )

        for line in file_output.split('\n'):
            line = line.strip()
            # Look for our filename in the output
            # Format: "164 audit_backup_20260319_221316.backup  backup  237.2KiB  2026-03-19 22:13:17"
            if filename in line and 'backup' in line.lower():
                # Extract size (3rd column in KiB format)
                parts = line.split()
                for i, part in enumerate(parts):
                    if 'KiB' in part or 'MiB' in part or 'GiB' in part:
                        try:
                            # Convert KiB/MiB/GiB to bytes
                            size_str = part.replace('KiB', '').replace('MiB', '').replace('GiB', '')
                            size = float(size_str)
                            if 'KiB' in part:
                                return int(size * 1024)
                            elif 'MiB' in part:
                                return int(size * 1024 * 1024)
                            elif 'GiB' in part:
                                return int(size * 1024 * 1024 * 1024)
                        except (ValueError, IndexError):
                            pass

        return None

    def _download_backup(
        self,
        filename: str,
        output_dir: Path,
        backup_result: BackupResult
    ):
        """Download backup file from router via SFTP."""
        logger.info(f"{Fore.CYAN}  Downloading backup file to {output_dir}...{Style.RESET_ALL}")

        try:
            with self.ssh.connection_pool.get_connection() as ssh_client:
                transport = ssh_client.get_transport()
                if not transport:
                    raise Exception("SSH transport not available")

                if not transport.is_active():
                    raise Exception("SSH transport is not active")

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

                # Find backup file (case-insensitive match)
                try:
                    remote_files = sftp.listdir('.')
                    matching_files = [f for f in remote_files if filename.lower() in f.lower()]
                    if matching_files:
                        filename = matching_files[0]
                        logger.info(f"Found remote file: {filename}")
                except Exception as list_err:
                    logger.warning(f"Could not list remote files: {list_err}")

                # Validate file extension is .backup
                if not filename.lower().endswith('.backup'):
                    logger.error(
                        f"Security: File '{filename}' is not a .backup file. "
                        f"Refusing to download."
                    )
                    backup_result.download_error = "Security: Invalid file type"
                    return backup_result

                local_path = output_dir / filename
                output_dir.mkdir(parents=True, exist_ok=True)

                # Download using context manager for proper cleanup
                try:
                    sftp.get(filename, str(local_path))
                finally:
                    sftp.close()

                if local_path.exists():
                    logger.info(
                        f"{Fore.GREEN}  ✓ Backup downloaded successfully{Style.RESET_ALL}: {local_path.name}"
                    )
                    backup_result.local_path = str(local_path)
                    backup_result.file_size = local_path.stat().st_size
                else:
                    logger.warning(f"Download completed but file not found at: {local_path}")
                    backup_result.download_error = "Download failed - file not found after transfer"

        except Exception as e:
            logger.warning(f"Failed to download backup file: {e}")
            backup_result.download_error = str(e)

    def _cleanup_backup(self, filename: str) -> None:
        """Delete backup file from router. Handles permission errors gracefully."""
        logger.info("Cleaning up backup file from router...")

        exit_status, output, stderr = self.ssh.execute_command(
            f'/file remove [find name="{filename}"]'
        )

        if exit_status == 0:
            logger.info(f"✓ Backup file removed from router: {filename}")
        else:
            error_msg = stderr or output
            permission_errors = [
                "permission denied",
                "insufficient privileges",
                "no write permission",
                "access denied",
            ]
            if any(err in error_msg.lower() for err in permission_errors):
                logger.debug(f"Cleanup skipped (permission denied): {filename}")
            else:
                logger.warning(
                    f"✗ Failed to remove backup file from router: {filename} - {error_msg}"
                )
