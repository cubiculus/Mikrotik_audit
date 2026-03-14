"""Tests for ssh_handler module."""

import pytest
from unittest.mock import patch, MagicMock
from src.config import RouterConfig
from src.ssh_handler import SSHHandler, SSHConnectionError, SSHConnectionPool


class TestSSHConnectionError:
    """Tests for SSHConnectionError exception."""

    def test_exception_message(self):
        """Test SSHConnectionError message."""
        error = SSHConnectionError("Test error message")
        assert str(error) == "Test error message"

    def test_exception_inheritance(self):
        """Test SSHConnectionError inherits from Exception."""
        error = SSHConnectionError("Test")
        assert isinstance(error, Exception)


class TestSSHConnectionPool:
    """Tests for SSHConnectionPool."""

    def test_pool_initialization(self):
        """Test pool initialization with default values."""
        config = RouterConfig()
        pool = SSHConnectionPool(config, max_connections=3)
        assert pool.max_connections == 3
        assert pool._active_connections == 0

    def test_pool_create_connection(self):
        """Test connection creation."""
        config = RouterConfig(
            router_ip="192.168.100.1",
            ssh_port=22,
            ssh_user="admin",
            ssh_pass="test"
        )
        pool = SSHConnectionPool(config, max_connections=3)

        # Mock paramiko to avoid actual connection
        with patch('src.ssh_handler.paramiko.SSHClient') as mock_client:
            mock_transport = MagicMock()
            mock_client.return_value.get_transport.return_value = mock_transport

            connection = pool._create_connection()

            assert connection is not None
            mock_client.return_value.connect.assert_called_once()

    def test_pool_create_connection_auth_error(self):
        """Test connection creation with authentication error."""
        import paramiko
        config = RouterConfig()
        pool = SSHConnectionPool(config, max_connections=3)

        with patch('src.ssh_handler.paramiko.SSHClient') as mock_client:
            mock_client.return_value.connect.side_effect = paramiko.AuthenticationException("Auth failed")

            with pytest.raises(SSHConnectionError) as exc_info:
                pool._create_connection()

            assert "Authentication failed" in str(exc_info.value)

    def test_pool_create_connection_ssh_error(self):
        """Test connection creation with SSH error."""
        import paramiko
        config = RouterConfig()
        pool = SSHConnectionPool(config, max_connections=3)

        with patch('src.ssh_handler.paramiko.SSHClient') as mock_client:
            mock_client.return_value.connect.side_effect = paramiko.SSHException("SSH error")

            with pytest.raises(SSHConnectionError) as exc_info:
                pool._create_connection()

            assert "SSH error" in str(exc_info.value)

    def test_is_connection_alive_false(self):
        """Test connection alive check with dead connection."""
        config = RouterConfig()
        pool = SSHConnectionPool(config, max_connections=3)

        mock_client = MagicMock()
        mock_client.get_transport.return_value = None

        assert pool._is_connection_alive(mock_client) is False

    def test_is_connection_alive_exception(self):
        """Test connection alive check with exception."""
        config = RouterConfig()
        pool = SSHConnectionPool(config, max_connections=3)

        mock_client = MagicMock()
        mock_client.get_transport.side_effect = Exception("Test error")

        assert pool._is_connection_alive(mock_client) is False

    def test_close_all(self):
        """Test closing all connections."""
        config = RouterConfig()
        pool = SSHConnectionPool(config, max_connections=3)

        # Add mock connections to pool
        mock_conn1 = MagicMock()
        mock_conn2 = MagicMock()
        pool._pool.put(mock_conn1)
        pool._pool.put(mock_conn2)

        pool.close_all()

        mock_conn1.close.assert_called_once()
        mock_conn2.close.assert_called_once()
        assert pool._active_connections == 0


class TestSSHHandler:
    """Tests for SSHHandler."""

    def test_handler_initialization(self):
        """Test SSHHandler initialization."""
        config = RouterConfig()
        handler = SSHHandler(config)

        assert handler.config == config
        assert handler.connection_pool is not None

    def test_handler_connect_success(self):
        """Test successful connection."""
        config = RouterConfig()
        handler = SSHHandler(config)

        mock_conn = MagicMock()
        mock_conn.exec_command.return_value = (MagicMock(), MagicMock(), MagicMock())
        mock_conn.exec_command.return_value[1].channel.recv_exit_status.return_value = 0
        mock_conn.exec_command.return_value[1].read.return_value = b""
        mock_conn.exec_command.return_value[2].read.return_value = b""

        with patch.object(handler.connection_pool, 'get_connection') as mock_get:
            mock_get.return_value.__enter__.return_value = mock_conn

            # connect() now just tests pool health, doesn't store connection
            handler.connect()

            # Just verify it completed without error
            mock_get.assert_called_once()

    def test_handler_connect_failure(self):
        """Test failed connection."""
        config = RouterConfig()
        handler = SSHHandler(config)

        with patch.object(handler.connection_pool, 'get_connection') as mock_get:
            mock_get.side_effect = SSHConnectionError("Connection failed")

            with pytest.raises(SSHConnectionError):
                handler.connect()

    def test_handler_execute_command(self):
        """Test command execution."""
        config = RouterConfig()
        handler = SSHHandler(config)

        mock_conn = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_conn.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stdout.read.return_value = b"output"
        mock_stderr.read.return_value = b""

        with patch.object(handler.connection_pool, 'get_connection') as mock_get:
            mock_get.return_value.__enter__.return_value = mock_conn

            exit_status, stdout, stderr = handler.execute_command("/test command")

            assert exit_status == 0
            assert stdout == "output"
            assert stderr == ""

    def test_handler_execute_command_error(self):
        """Test command execution with error."""
        config = RouterConfig()
        handler = SSHHandler(config)

        with patch.object(handler.connection_pool, 'get_connection') as mock_get:
            mock_get.side_effect = SSHConnectionError("Command failed")

            with pytest.raises(SSHConnectionError):
                handler.execute_command("/test command")

    def test_handler_close(self):
        """Test closing handler."""
        config = RouterConfig()
        handler = SSHHandler(config)

        with patch.object(handler.connection_pool, 'close_all') as mock_close:
            handler.close()
            mock_close.assert_called_once()

    def test_get_version_info_identity_error(self):
        """Test get_version_info with identity error."""
        config = RouterConfig()
        handler = SSHHandler(config)

        with patch.object(handler, 'execute_command') as mock_exec:
            mock_exec.side_effect = SSHConnectionError("Failed")

            info = handler.get_version_info()

            assert info["identity"] == "Unknown"

    def test_get_version_info_parsing(self):
        """Test get_version_info parsing."""
        config = RouterConfig()
        handler = SSHHandler(config)

        identity_output = "name: TestRouter"
        resource_output = """version: 7.10
uptime: 1h
board-name: RB750
architecture-name: arm
cpu-count: 2"""

        with patch.object(handler, 'execute_command') as mock_exec:
            mock_exec.side_effect = [
                (0, identity_output, ""),
                (0, resource_output, ""),
                (0, "", "")
            ]

            info = handler.get_version_info()

            assert info["identity"] == "TestRouter"
            assert info["version"] == "7.10"
            assert info["cpu_count"] == 2
