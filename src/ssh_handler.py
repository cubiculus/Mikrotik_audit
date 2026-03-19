"""SSH connection handler for MikroTik RouterOS with connection pooling."""

import paramiko
import logging
import re
import os
import stat
from typing import Any, Tuple
from contextlib import contextmanager
from queue import Queue, Empty
from threading import Lock
from pathlib import Path
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from src.config import RouterConfig

logger = logging.getLogger(__name__)


def _sanitize_command(command: str) -> str:
    """
    Sanitize command string to prevent shell injection attacks.

    Only allows safe characters for MikroTik RouterOS commands.
    Blocks dangerous shell metacharacters.

    Returns only the first safe segment of the command.
    If dangerous characters are found, the command is truncated at that point.
    """
    # Remove dangerous shell metacharacters
    # Note: ! is NOT removed as it's RouterOS negation operator (e.g., routing-mark!="")
    # Note: ~ is NOT removed as it's RouterOS regex match operator (e.g., topics~"firewall")
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\\']

    # Find the first dangerous character and truncate the command there
    for i, char in enumerate(command):
        if char in dangerous_chars:
            logger.warning(f"Dangerous character '{char}' detected at position {i}, truncating command")
            command = command[:i]
            break

    # Allow only safe characters for RouterOS commands
    # RouterOS commands use: alphanumeric, /, -, _, :, ., space, =, [, ], ", ', !, ~, ,
    # ! is negation operator (e.g., routing-mark!="")
    # ~ is regex match operator (e.g., topics~"firewall")
    # , is used in port lists (e.g., dst-port=[80,443])
    safe_pattern = re.compile(r'^[a-zA-Z0-9/\-_\:\.\s=\[\]"\'!~,]+$')

    if not safe_pattern.match(command.strip()):
        # If command still has unsafe characters, log warning and return empty
        # This handles cases where command starts with unsafe chars
        logger.warning(f"Command contains unsafe characters after sanitization: {command}")
        # Strip and keep only the safe prefix
        stripped = command.strip()
        for i, char in enumerate(stripped):
            if not safe_pattern.match(stripped[:i+1]):
                logger.warning(f"Truncating at unsafe character at position {i}")
                return stripped[:i]

    return command.strip()


class SSHConnectionError(Exception):
    """Custom exception for SSH connection errors."""
    pass


class SSHConnectionPool:
    """Пул SSH-соединений для переиспользования."""

    def __init__(self, config: RouterConfig, max_connections: int = 3) -> None:
        self.config = config
        self.max_connections = max_connections
        self._pool: Queue = Queue(maxsize=max_connections)
        self._lock = Lock()
        self._active_connections = 0
        self._issued_connections: set[int] = set()  # Track connections currently in use

    @contextmanager
    def get_connection(self) -> Any:
        """Получить соединение из пула."""
        conn = None

        try:
            # Пытаемся получить из пула без блокировки
            if not self._pool.empty():
                try:
                    conn = self._pool.get_nowait()
                    # Проверяем, живо ли соединение
                    if self._is_connection_alive(conn):
                        logger.debug("Reusing existing SSH connection")
                    else:
                        conn = None
                        with self._lock:
                            self._active_connections -= 1
                except Empty:
                    conn = None

            # Если нет доступного, создаем новое или ждем
            if conn is None:
                # Пытаемся создать новое соединение с блокировкой
                with self._lock:
                    if self._active_connections < self.max_connections:
                        conn = self._create_connection()
                        self._active_connections += 1

                # Если не смогли создать (лимит достигнут), ждем освобождения БЕЗ блокировки
                if conn is None:
                    try:
                        conn = self._pool.get(timeout=self.config.connect_timeout)
                    except Empty:
                        raise SSHConnectionError(
                            f"Could not get connection from pool after {self.config.connect_timeout}s"
                        )

            yield conn
        finally:
            if conn:
                # Remove from issued set
                with self._lock:
                    self._issued_connections.discard(id(conn))

                # Return to pool if alive
                if self._is_connection_alive(conn):
                    self._pool.put(conn)
                else:
                    with self._lock:
                        self._active_connections -= 1

    def _validate_ssh_key_permissions(self, key_path: Path) -> None:
        """
        Validate SSH key file permissions are secure.

        Raises SSHConnectionError if key file has insecure permissions.

        Private SSH keys should only be readable by the owner.
        On Unix/Linux: permissions should be 0600 or stricter (0400).
        On Windows: file owner should be the current user.
        """
        try:
            file_stat = key_path.stat()
            mode = file_stat.st_mode

            # Check permissions on Unix/Linux/macOS
            if os.name != 'nt':  # Not Windows
                # Check if group or others have read permission
                if mode & (stat.S_IRGRP | stat.S_IROTH):
                    raise SSHConnectionError(
                        f"SSH key file {key_path} has insecure permissions. "
                        f"Permissions should be 0600 (owner only readable). "
                        f"Current permissions: {oct(stat.S_IMODE(mode))}. "
                        f"Run: chmod 600 {key_path}"
                    )

            # On Windows, check if file exists and is readable
            # (Windows uses ACLs, not Unix permissions, so we do basic checks)
            else:
                try:
                    # Try to read first few bytes to verify file is accessible
                    with open(key_path, 'rb') as f:
                        f.read(100)
                except (PermissionError, OSError) as e:
                    raise SSHConnectionError(
                        f"Cannot read SSH key file {key_path}: {e}. "
                        "Ensure you have the necessary permissions."
                    )

            logger.debug(f"SSH key permissions validated: {key_path}")

        except FileNotFoundError:
            raise SSHConnectionError(f"SSH key file not found: {key_path}")
        except SSHConnectionError:
            raise  # Re-raise our custom errors
        except Exception as e:
            logger.warning(f"Could not fully validate SSH key permissions: {e}")
            # Don't fail if we can't validate, but log it

    def _create_connection(self) -> paramiko.SSHClient:
        """Create a new SSH connection with validated credentials."""
        client = paramiko.SSHClient()
        # RejectPolicy prevents MITM attacks by rejecting unknown host keys
        # Host keys must be pre-added to known_hosts file for security
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            # Prepare connection parameters
            connect_kwargs = {
                "hostname": self.config.router_ip,
                "port": self.config.ssh_port,
                "username": self.config.ssh_user,
                "timeout": self.config.connect_timeout,
                "allow_agent": False,  # Disabled for MikroTik compatibility
                "look_for_keys": False,  # Disabled for MikroTik compatibility
                "auth_timeout": self.config.connect_timeout,
                "banner_timeout": 10,
                "compress": True,
            }

            # If SSH key file is specified, use it
            if self.config.ssh_key_file:
                key_path = Path(self.config.ssh_key_file).expanduser()

                # Validate SSH key permissions
                self._validate_ssh_key_permissions(key_path)

                connect_kwargs["key_filename"] = str(key_path)
                connect_kwargs["password"] = self.config.ssh_key_passphrase
                logger.info(f"Using SSH key: {key_path}")
            elif self.config.ssh_pass:
                # Use password authentication
                connect_kwargs["password"] = self.config.ssh_pass
                logger.info("Using password authentication")
            else:
                # Try authentication via ssh-agent or default keys
                logger.info("Using SSH agent or default keys for authentication")

            client.connect(**connect_kwargs)

            # Configure keepalive after connection
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(30)
            return client
        except paramiko.AuthenticationException as e:
            raise SSHConnectionError(f"Authentication failed: {e}")
        except paramiko.SSHException as e:
            raise SSHConnectionError(f"SSH error: {e}")
        except Exception as e:
            raise SSHConnectionError(f"Connection failed: {e}")

    def _is_connection_alive(self, client: paramiko.SSHClient) -> bool:
        """Проверить, активно ли соединение."""
        try:
            transport = client.get_transport()
            if transport and transport.is_active():
                transport.send_ignore()
                return True
        except Exception as e:
            logger.debug(f"Connection check failed: {e}")
        return False

    def close_all(self) -> None:
        """Close all connections including those currently in use."""
        # Close all connections in the pool
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                try:
                    conn.close()
                except Exception as e:
                    logger.debug(f"Error closing connection: {e}")
            except Empty:
                break

        # Note: We cannot close connections currently issued (in use) as they're
        # being held by other threads. They will be checked for liveness
        # on next checkout and closed if dead.
        with self._lock:
            self._active_connections = 0
            self._issued_connections.clear()


class SSHHandler:
    """Улучшенный обработчик SSH соединений."""

    def __init__(self, config: RouterConfig):
        """Initialize SSH handler with router config."""
        self.config = config
        self.connection_pool = SSHConnectionPool(config, max_connections=3)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(SSHConnectionError),
        reraise=True
    )
    def connect(self) -> None:
        """
        Проверка доступности пула соединений.

        Этот метод больше не создает постоянное соединение — пул управляет соединениями автоматически.
        Вызывается для проверки возможности подключения.
        """
        try:
            # Просто проверяем возможность получения соединения
            with self.connection_pool.get_connection() as conn:
                # Проверяем соединение тестовой командой (хардкод, безопасно)
                conn.exec_command("/system clock print", timeout=5)  # nosec B601
                logger.info("Connection pool is healthy")
        except SSHConnectionError as e:
            logger.error(f"Failed to connect: {e}")
            raise

    def execute_command(self, command: str) -> Tuple[int, str, str]:
        """Выполнить команду (использует пул соединений)."""
        # Sanitize command to prevent shell injection
        sanitized_command = _sanitize_command(command)

        # Use timeout_per_command if set, otherwise use default command_timeout
        timeout = self.config.timeout_per_command or self.config.command_timeout

        with self.connection_pool.get_connection() as conn:
            try:
                stdin, stdout, stderr = conn.exec_command(
                    sanitized_command,
                    timeout=timeout
                )  # nosec B601
                exit_status = stdout.channel.recv_exit_status()
                out = stdout.read().decode('utf-8', errors='ignore')
                err = stderr.read().decode('utf-8', errors='ignore')
                return exit_status, out, err
            except paramiko.SSHException as e:
                logger.error(f"SSH error executing command '{command}': {e}")
                raise SSHConnectionError(f"Command execution failed: {e}")
            except Exception as e:
                logger.error(f"Command execution failed: {e}")
                raise SSHConnectionError(f"Command execution failed: {e}")

    def get_version_info(self) -> dict:
        """Get RouterOS version and system information."""
        version_info = {
            "identity": "Unknown",
            "version": "Unknown",
            "model": "MikroTik Router",
            "board_name": "Unknown",
            "architecture": "Unknown",
            "uptime": "Unknown",
            "cpu_count": 1,
        }

        try:
            exit_status, output, _ = self.execute_command("/system identity print")
            for line in output.split('\n'):
                if 'name:' in line.lower():
                    version_info["identity"] = line.split(':', 1)[1].strip()
                    break
        except SSHConnectionError as e:
            logger.warning(f"Could not get identity: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error getting identity: {e}")

        try:
            exit_status, output, _ = self.execute_command("/system resource print")
            for line in output.split('\n'):
                line_lower = line.lower()
                if 'version:' in line_lower:
                    version_info["version"] = line.split(':', 1)[1].strip()
                elif 'uptime:' in line_lower:
                    version_info["uptime"] = line.split(':', 1)[1].strip()
                elif 'board-name:' in line_lower:
                    version_info["model"] = line.split(':', 1)[1].strip()
                elif 'architecture-name:' in line_lower:
                    version_info["architecture"] = line.split(':', 1)[1].strip()
                elif 'cpu-count:' in line_lower:
                    try:
                        version_info["cpu_count"] = int(line.split(':', 1)[1].strip())
                    except ValueError:
                        logger.warning(f"Could not parse CPU count: {line}")
        except SSHConnectionError as e:
            logger.warning(f"Could not get resource info: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error getting resource info: {e}")

        # Примечание: серийный номер НЕ запрашивается намеренно (требования безопасности)
        # /system routerboard print содержит serial-number, но мы его не извлекаем

        return version_info

    def close(self) -> None:
        """Закрыть все соединения."""
        self.connection_pool.close_all()
        logger.info("All SSH connections closed")
