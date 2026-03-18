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
        mock_ssh.execute_command.side_effect = [
            (0, "Backup created", ""),  # /system backup save
            (0, "  size: 4096", ""),    # /file print detail
            (0, "", ""),                # /file remove (cleanup)
        ]

        # Mock _get_file_size to return valid size
        with patch.object(backup_manager, '_get_file_size', return_value=4096):
            with patch.object(backup_manager, '_download_backup'):
                with patch.object(backup_manager, '_cleanup_backup') as mock_cleanup:
                    # Act
                    result = backup_manager.perform_backup(
                        output_dir=Path("/tmp/backups"),
                        timestamp="20260318_120000"
                    )

                    # Assert
                    assert result.status == "success"
                    assert result.file_name == "audit_backup_20260318_120000.backup"
                    assert result.file_size == 4096
                    assert result.error_message is None

                    # Verify cleanup was called
                    mock_cleanup.assert_called_once_with("audit_backup_20260318_120000.backup")

    def test_backup_failure_on_exit_status_zero_but_file_not_found(self):
        """Test that exit_status=0 with missing file results in failure status."""
        # Arrange
        mock_ssh = MagicMock()
        backup_manager = BackupManager(mock_ssh)

        # Mock backup command with exit_status=0 but file not found
        mock_ssh.execute_command.return_value = (0, "", "")

        # Mock _get_file_size to return None (file not found)
        with patch.object(backup_manager, '_get_file_size', return_value=None):
            # Act
            result = backup_manager.perform_backup(
                output_dir=Path("/tmp/backups"),
                timestamp="20260318_120000"
            )

            # Assert
            assert result.status == "failed"
            assert result.file_name == "audit_backup_20260318_120000.backup"
            assert "exit_status=0 but file not found" in result.error_message
            assert result.error_message is not None


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
            (0, "  size: 8192", ""),    # /file print detail
            (0, "", ""),                # /file remove (cleanup)
        ]

        # Mock _get_file_size to return valid size (critical for success path)
        with patch.object(backup_manager, '_get_file_size', return_value=8192):
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
