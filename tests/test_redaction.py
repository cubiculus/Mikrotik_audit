"""Tests for IP address redaction functionality."""

from src.config import redact_sensitive_data


class TestIPRedaction:
    """Tests for IP address redaction in sensitive data."""

    def test_public_ip_redaction(self):
        """Test that public IP addresses are masked."""
        text = "Server IP: 8.8.8.8 and 1.1.1.1"
        result = redact_sensitive_data(text)
        assert "8.8.8.***" in result
        assert "1.1.1.***" in result

    def test_private_ip_192_168_not_redacted(self):
        """Test that 192.168.x.x private IPs are NOT masked."""
        text = "Router: 192.168.1.1 Gateway: 192.168.0.1"
        result = redact_sensitive_data(text)
        assert "192.168.1.1" in result
        assert "192.168.0.1" in result
        assert "192.168" not in result or "***" not in result

    def test_private_ip_10_x_not_redacted(self):
        """Test that 10.x.x.x private IPs are NOT masked."""
        text = "Network: 10.0.0.1 and 10.255.255.254"
        result = redact_sensitive_data(text)
        assert "10.0.0.1" in result
        assert "10.255.255.254" in result

    def test_private_ip_172_16_31_not_redacted(self):
        """Test that 172.16-31.x.x private IPs are NOT masked."""
        text = "Networks: 172.16.0.1, 172.20.5.10, 172.31.255.254"
        result = redact_sensitive_data(text)
        assert "172.16.0.1" in result
        assert "172.20.5.10" in result
        assert "172.31.255.254" in result

    def test_private_ip_172_15_is_redacted(self):
        """Test that 172.15.x.x (not in private range) IS masked."""
        text = "Server: 172.15.0.1"
        result = redact_sensitive_data(text)
        assert "172.15.0.***" in result or "***" in result

    def test_private_ip_172_32_is_redacted(self):
        """Test that 172.32.x.x (not in private range) IS masked."""
        text = "Server: 172.32.0.1"
        result = redact_sensitive_data(text)
        assert "172.32.0.***" in result or "***" in result

    def test_loopback_127_not_redacted(self):
        """Test that loopback 127.x.x.x is NOT masked."""
        text = "Loopback: 127.0.0.1, 127.0.0.53"
        result = redact_sensitive_data(text)
        assert "127.0.0.1" in result
        assert "127.0.0.53" in result

    def test_link_local_169_254_not_redacted(self):
        """Test that link-local 169.254.x.x is NOT masked."""
        text = "Link-local: 169.254.1.1"
        result = redact_sensitive_data(text)
        assert "169.254.1.1" in result

    def test_multicast_not_redacted(self):
        """Test that multicast addresses are NOT masked."""
        text = "Multicast: 224.0.0.1, 239.255.255.250"
        result = redact_sensitive_data(text)
        assert "224.0.0.1" in result
        assert "239.255.255.250" in result

    def test_serial_number_redaction(self):
        """Test that serial numbers are redacted."""
        text = "Serial: ABCD1234 serial-number: EFGH5678"
        result = redact_sensitive_data(text)
        assert "[REDACTED]" in result
        assert "ABCD1234" not in result
        assert "EFGH5678" not in result

    def test_password_redaction(self):
        """Test that passwords are redacted."""
        text = "password=pass1234 ppp-secret=hidden"
        result = redact_sensitive_data(text)
        assert "[REDACTED]" in result
        assert "pass1234" not in result
        assert "hidden" not in result

    def test_mixed_redaction(self):
        """Test mixed content with various sensitive data."""
        text = """
        IP: 8.8.8.8
        Private IP: 192.168.100.1
        Serial: ABCD1234
        Password: pass1234
        """
        result = redact_sensitive_data(text)
        # Public IP should be masked
        assert "8.8.8.***" in result
        # Private IP should NOT be masked
        assert "192.168.100.1" in result
        # Serial should be masked
        assert "[REDACTED]" in result
        assert "ABCD1234" not in result
        # Password should be masked
        assert "pass1234" not in result

    def test_empty_text(self):
        """Test that empty text is handled correctly."""
        result = redact_sensitive_data("")
        assert result == ""

    def test_none_input(self):
        """Test that None input is handled correctly."""
        result = redact_sensitive_data(None)
        assert result is None
