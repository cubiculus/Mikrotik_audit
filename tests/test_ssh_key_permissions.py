"""Tests for SSH key permission validation."""

import pytest
import os
import tempfile
from pathlib import Path

from src.config import RouterConfig
from src.ssh_handler import SSHConnectionError, SSHConnectionPool


class TestSSHKeyPermissions:
    """Tests for SSH key file permission validation."""

    def test_ssh_key_permissions_insecure_group_readable(self):
        """Test that SSH key with group-read permissions raises error on Unix."""
        if os.name == 'nt':  # Windows - skip this test
            pytest.skip("Unix permissions test not applicable on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / "test_key"
            key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")

            # Make file group-readable (insecure)
            os.chmod(key_file, 0o640)  # rw-r-----

            config = RouterConfig(
                router_ip="192.168.100.1",
                ssh_port=22,
                ssh_user="test",
                ssh_key_file=str(key_file)
            )
            pool = SSHConnectionPool(config, max_connections=3)

            with pytest.raises(SSHConnectionError) as exc_info:
                pool._validate_ssh_key_permissions(key_file)

            assert "insecure permissions" in str(exc_info.value).lower()
            assert "0600" in str(exc_info.value)

    def test_ssh_key_permissions_insecure_others_readable(self):
        """Test that SSH key with others-read permissions raises error on Unix."""
        if os.name == 'nt':  # Windows - skip this test
            pytest.skip("Unix permissions test not applicable on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / "test_key"
            key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")

            # Make file others-readable (very insecure)
            os.chmod(key_file, 0o644)  # rw-r--r--

            config = RouterConfig(
                router_ip="192.168.100.1",
                ssh_port=22,
                ssh_user="test",
                ssh_key_file=str(key_file)
            )
            pool = SSHConnectionPool(config, max_connections=3)

            with pytest.raises(SSHConnectionError) as exc_info:
                pool._validate_ssh_key_permissions(key_file)

            assert "insecure permissions" in str(exc_info.value).lower()

    def test_ssh_key_permissions_secure(self):
        """Test that SSH key with correct permissions passes validation on Unix."""
        if os.name == 'nt':  # Windows - skip this test
            pytest.skip("Unix permissions test not applicable on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / "test_key"
            key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")

            # Make file owner-only readable (secure)
            os.chmod(key_file, 0o600)  # rw-------

            config = RouterConfig(
                router_ip="192.168.100.1",
                ssh_port=22,
                ssh_user="test",
                ssh_key_file=str(key_file)
            )
            pool = SSHConnectionPool(config, max_connections=3)

            # Should not raise any exception
            pool._validate_ssh_key_permissions(key_file)

    def test_ssh_key_windows_basic_check(self):
        """Test that SSH key basic validation works on Windows."""
        if os.name != 'nt':  # Skip on Unix
            pytest.skip("Windows-specific test")

        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / "test_key"
            key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")

            config = RouterConfig(
                router_ip="192.168.100.1",
                ssh_port=22,
                ssh_user="test",
                ssh_key_file=str(key_file)
            )
            pool = SSHConnectionPool(config, max_connections=3)

            # Should not raise any exception (Windows uses ACLs, not Unix permissions)
            pool._validate_ssh_key_permissions(key_file)

    def test_ssh_key_not_found(self):
        """Test that missing SSH key file raises error."""
        config = RouterConfig(
            router_ip="192.168.100.1",
            ssh_port=22,
            ssh_user="test",
            ssh_key_file="/nonexistent/key.pem"
        )
        pool = SSHConnectionPool(config, max_connections=3)

        with pytest.raises(SSHConnectionError) as exc_info:
            pool._validate_ssh_key_permissions(Path("/nonexistent/key.pem"))

        assert "not found" in str(exc_info.value).lower()
