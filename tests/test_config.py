"""Tests for config module."""

import pytest
from pydantic import ValidationError

from src.config import RouterConfig, AuditConfig, AuditLevel


class TestRouterConfig:
    """Tests for RouterConfig validation."""

    def test_default_values(self, monkeypatch):
        """Test default configuration values."""
        # Clear environment variables to test defaults
        monkeypatch.delenv("MIKROTIK_IP", raising=False)
        monkeypatch.delenv("MIKROTIK_PORT", raising=False)
        monkeypatch.delenv("MIKROTIK_USER", raising=False)
        monkeypatch.delenv("MIKROTIK_PASSWORD", raising=False)

        config = RouterConfig()
        assert config.router_ip == "192.168.100.1"
        assert config.ssh_port == 22
        assert config.ssh_user == "admin"
        assert config.connect_timeout == 30
        assert config.command_timeout == 120
        assert config.max_retries == 3

    def test_custom_values(self):
        """Test custom configuration values."""
        config = RouterConfig(
            router_ip="192.168.100.1",
            ssh_port=2222,
            ssh_user="test_user",
            ssh_pass="test_pass"
        )
        assert config.router_ip == "192.168.100.1"
        assert config.ssh_port == 2222
        assert config.ssh_user == "test_user"
        assert config.ssh_pass == "test_pass"

    def test_valid_port_range(self):
        """Test valid SSH port values."""
        # Minimum valid port
        config = RouterConfig(ssh_port=1)
        assert config.ssh_port == 1

        # Maximum valid port
        config = RouterConfig(ssh_port=65535)
        assert config.ssh_port == 65535

        # Common SSH port
        config = RouterConfig(ssh_port=22)
        assert config.ssh_port == 22

    def test_invalid_port_zero(self):
        """Test that port 0 raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            RouterConfig(ssh_port=0)
        assert "SSH port must be between 1 and 65535" in str(exc_info.value)

    def test_invalid_port_negative(self):
        """Test that negative port raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            RouterConfig(ssh_port=-1)
        assert "SSH port must be between 1 and 65535" in str(exc_info.value)

    def test_invalid_port_too_high(self):
        """Test that port > 65535 raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            RouterConfig(ssh_port=65536)
        assert "SSH port must be between 1 and 65535" in str(exc_info.value)

    def test_invalid_timeout_zero(self):
        """Test that zero timeout raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            RouterConfig(connect_timeout=0)
        assert "connect_timeout must be positive" in str(exc_info.value)

    def test_invalid_timeout_negative(self):
        """Test that negative timeout raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            RouterConfig(command_timeout=-10)
        assert "command_timeout must be positive" in str(exc_info.value)

    def test_invalid_max_retries_zero(self):
        """Test that zero max_retries raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            RouterConfig(max_retries=0)
        assert "max_retries must be positive" in str(exc_info.value)

    def test_environment_variables(self, monkeypatch):
        """Test that environment variables are loaded correctly."""
        monkeypatch.setenv("MIKROTIK_IP", "192.168.100.1")
        monkeypatch.setenv("MIKROTIK_PORT", "2222")
        monkeypatch.setenv("MIKROTIK_USER", "env_user")
        monkeypatch.setenv("MIKROTIK_PASSWORD", "env_pass")

        config = RouterConfig()
        assert config.router_ip == "192.168.100.1"
        assert config.ssh_port == 2222
        assert config.ssh_user == "env_user"
        assert config.ssh_pass == "env_pass"


class TestAuditConfig:
    """Tests for AuditConfig."""

    def test_default_values(self):
        """Test default AuditConfig values."""
        config = AuditConfig()
        assert config.audit_level == AuditLevel.STANDARD
        assert config.skip_security_check is False
        assert config.output_dir is None
        assert config.max_workers == 0  # 0 = auto-calculate
        assert isinstance(config.router, RouterConfig)

    def test_custom_values(self):
        """Test custom AuditConfig values."""
        config = AuditConfig(
            audit_level=AuditLevel.COMPREHENSIVE,
            skip_security_check=True,
            output_dir="/tmp/audit",
            max_workers=10
        )
        assert config.audit_level == AuditLevel.COMPREHENSIVE
        assert config.skip_security_check is True
        assert config.output_dir == "/tmp/audit"
        assert config.max_workers == 10

    def test_audit_level_enum(self):
        """Test AuditLevel enum values."""
        assert AuditLevel.BASIC.value == "Basic"
        assert AuditLevel.STANDARD.value == "Standard"
        assert AuditLevel.COMPREHENSIVE.value == "Comprehensive"
