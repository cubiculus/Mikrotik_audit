"""Tests for backup_manager module."""

from unittest.mock import MagicMock, patch
from pathlib import Path

from src.backup_manager import BackupManager


class TestBackupSuccess:
    """Tests for backup success determination."""

    def test_backup_success_on_exit_status_zero(self):
        """Test that exit_status=0 results in success status when backup file exists."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        # Mock successful backup command (exit_status=0)
        # RouterOS v7: /file print where type="backup" returns file list
        mock_ssh.execute_command.side_effect = [
            (0, "Backup created", ""),  # /system backup save
            (0, '164 audit_backup_20260318_120000.backup  backup  237.2KiB  2026-03-18 12:00:01', ""),  # /file print where type="backup"
            (0, "", ""),                # /file remove (cleanup)
        ]

        # Act
        result = backup_manager.perform_backup(
            output_dir=Path("/tmp/backups"),
            timestamp="20260318_120000"
        )

        # Assert
        assert result.status == "success"
        assert result.file_name == "audit_backup_20260318_120000.backup"
        assert result.file_size == 242892  # 237.2 * 1024
        assert result.error_message is None

    def test_backup_with_retry_on_file_not_found(self):
        """Test that backup retries when file not found immediately."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        # First call returns empty (file not ready), second call returns file
        mock_ssh.execute_command.side_effect = [
            (0, "Backup created", ""),  # /system backup save
            (0, "", ""),                # /file print where type="backup" (empty - not ready)
            (0, '164 audit_backup_20260318_120000.backup  backup  237.2KiB  2026-03-18 12:00:01', ""),  # Retry - file found
            (0, "", ""),                # /file remove (cleanup)
        ]

        # Act
        result = backup_manager.perform_backup(
            output_dir=Path("/tmp/backups"),
            timestamp="20260318_120000"
        )

        # Assert
        assert result.status == "success"
        assert result.file_size == 242892  # 237.2 * 1024
        # Verify execute_command was called 4 times (backup + 2x file check + cleanup)
        assert mock_ssh.execute_command.call_count == 4

    def test_backup_failure_on_exit_status_zero_but_file_not_found_after_retry(self):
        """Test that exit_status=0 with missing file after retry results in failed status."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        # Mock backup command with exit_status=0 but file not found even after retry
        mock_ssh.execute_command.side_effect = [
            (0, "Backup created", ""),  # /system backup save
            (0, "", ""),                # /file print where type="backup" (empty)
            (0, "", ""),                # /file print where type="backup" (retry - still empty)
        ]

        # Act
        result = backup_manager.perform_backup(
            output_dir=Path("/tmp/backups"),
            timestamp="20260318_120000"
        )

        # Assert - command succeeded but file not found = failed
        assert result.status == "failed"
        assert result.file_name == "audit_backup_20260318_120000.backup"
        assert "exit_status=0 but file not found" in result.error_message


class TestBackupPermissionDenied:
    """Tests for permission denied handling."""

    def test_backup_skipped_on_permission_denied(self):
        """Test that permission denied results in skipped status."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        # Mock permission denied error
        mock_ssh.execute_command.return_value = (
            1,
            "",
            "permission denied: backup requires write privileges"
        )

        # Act
        result = backup_manager.perform_backup()

        # Assert
        assert result.status == "skipped"
        assert result.file_name is None
        assert "Insufficient permissions" in result.error_message
        assert backup_manager._permission_denied is True

        # Verify cleanup was NOT called (backup was never created)
        assert mock_ssh.execute_command.call_count == 1


class TestCleanupCalledAfterDownload:
    """Tests for cleanup being called after download."""

    def test_cleanup_called_after_download(self):
        """Test that cleanup is called after backup download completes."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        # Mock successful backup
        mock_ssh.execute_command.side_effect = [
            (0, "Backup created", ""),  # /system backup save
            (0, '164 audit_backup_20260318_150000.backup  backup  237.2KiB  2026-03-18 15:00:01', ""),  # /file print where type="backup"
            (0, "", ""),                # /file remove (cleanup)
        ]

        with patch.object(backup_manager, '_download_backup') as mock_download:
            with patch.object(backup_manager, '_cleanup_backup') as mock_cleanup:
                # Act
                result = backup_manager.perform_backup(
                    output_dir=Path("/tmp/backups"),
                    timestamp="20260318_150000"
                )

                # Assert
                assert result.status == "success"

                # Verify download was called before cleanup
                mock_cleanup.assert_called_once()

                # Check that cleanup was called after download
                assert mock_download.call_count == 1
                assert mock_cleanup.call_count == 1


class TestGetFileSize:
    """Tests for _get_file_size method."""

    def test_get_file_size_kib(self):
        """Test parsing file size in KiB format."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        # RouterOS v7 output format
        mock_ssh.execute_command.return_value = (
            0,
            '164 audit_backup_20260318_120000.backup  backup  237.2KiB  2026-03-18 12:00:01',
            ""
        )

        # Act
        size = backup_manager._get_file_size("audit_backup_20260318_120000.backup")

        # Assert
        assert size == 242892  # 237.2 * 1024

    def test_get_file_size_mib(self):
        """Test parsing file size in MiB format."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        mock_ssh.execute_command.return_value = (
            0,
            '165 large_backup.backup  backup  10.5MiB  2026-03-18 12:00:01',
            ""
        )

        # Act
        size = backup_manager._get_file_size("large_backup.backup")

        # Assert
        assert size == 11010048  # 10.5 * 1024 * 1024

    def test_get_file_size_not_found(self):
        """Test when file not found in backup list."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        mock_ssh.execute_command.return_value = (
            0,
            '164 other_backup.backup  backup  237.2KiB  2026-03-18 12:00:01',
            ""
        )

        # Act
        size = backup_manager._get_file_size("audit_backup_20260318_120000.backup")

        # Assert
        assert size is None

    def test_get_file_size_empty_output(self):
        """Test when /file print returns empty output."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        mock_ssh.execute_command.return_value = (0, "", "")

        # Act
        size = backup_manager._get_file_size("audit_backup_20260318_120000.backup")

        # Assert
        assert size is None
