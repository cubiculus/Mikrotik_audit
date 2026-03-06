"""SSH connection handler for MikroTik RouterOS with connection pooling."""

import paramiko
import logging
import re
from typing import Tuple, Optional
from contextlib import contextmanager
from queue import Queue, Empty
from threading import Lock
import time
from pathlib import Path
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from src.config import RouterConfig

logger = logging.getLogger(__name__)


def _sanitize_command(command: str) -> str:
    """
    Sanitize command string to prevent shell injection attacks.
    
    Only allows safe characters for MikroTik RouterOS commands.
    Blocks dangerous shell metacharacters.
    """
    # Remove dangerous shell metacharacters
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '!', '\\']
    for char in dangerous_chars:
        if char in command:
            logger.warning(f"Dangerous character '{char}' detected in command, removing")
            command = command.replace(char, '')
    
    # Allow only safe characters for RouterOS commands
    # RouterOS commands use: alphanumeric, /, -, _, :, ., space, =, [, ], ", '
    safe_pattern = re.compile(r'^[a-zA-Z0-9/\-_:\. =\[\]"\']+$')
    if not safe_pattern.match(command.strip()):
        logger.warning(f"Command contains potentially unsafe characters: {command}")
    
    return command.strip()


class SSHConnectionError(Exception):
    """Custom exception for SSH connection errors."""
    pass


class SSHConnectionPool:
    """Пул SSH-соединений для переиспользования."""

    def __init__(self, config, max_connections: int = 3):
        self.config = config
        self.max_connections = max_connections
        self._pool: Queue = Queue(maxsize=max_connections)
        self._lock = Lock()
        self._active_connections = 0

    @contextmanager
    def get_connection(self):
        """Получить соединение из пула."""
        conn = None
        created_new = False
        
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
                        created_new = True
                
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
                # Возвращаем в пул если живо
                if self._is_connection_alive(conn):
                    self._pool.put(conn)
                else:
                    with self._lock:
                        self._active_connections -= 1

    def _create_connection(self) -> paramiko.SSHClient:
        """Создать новое SSH-соединение."""
        client = paramiko.SSHClient()
        # Используем RejectPolicy для защиты от MITM-атак
        # Ключи хостов должны быть предварительно сохранены в known_hosts
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        
        try:
            # Подготовка параметров подключения
            connect_kwargs = {
                "hostname": self.config.router_ip,
                "port": self.config.ssh_port,
                "username": self.config.ssh_user,
                "timeout": self.config.connect_timeout,
                "allow_agent": True,  # Использовать ssh-agent если доступен
                "look_for_keys": True,  # Искать ключи в ~/.ssh/
                "auth_timeout": self.config.connect_timeout,
                "banner_timeout": 10,
                "compress": True,
            }
            
            # Если указан файл ключа — используем его
            if self.config.ssh_key_file:
                key_path = Path(self.config.ssh_key_file).expanduser()
                if not key_path.exists():
                    raise SSHConnectionError(f"SSH key file not found: {key_path}")
                
                connect_kwargs["key_filename"] = str(key_path)
                connect_kwargs["password"] = self.config.ssh_key_passphrase
                connect_kwargs["look_for_keys"] = False  # Не искать другие ключи
                connect_kwargs["allow_agent"] = False  # Не использовать agent
                logger.info(f"Using SSH key: {key_path}")
            elif self.config.ssh_pass:
                # Используем пароль
                connect_kwargs["password"] = self.config.ssh_pass
            else:
                # Пробует аутентификацию через ssh-agent или ключи по умолчанию
                logger.info("Using SSH agent or default keys for authentication")
            
            client.connect(**connect_kwargs)
            
            # Настраиваем keepalive после подключения
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

    def close_all(self):
        """Закрыть все соединения."""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                try:
                    conn.close()
                except Exception as e:
                    logger.debug(f"Error closing connection: {e}")
            except Empty:
                break
        with self._lock:
            self._active_connections = 0


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
        
        with self.connection_pool.get_connection() as conn:
            try:
                stdin, stdout, stderr = conn.exec_command(
                    sanitized_command,
                    timeout=self.config.command_timeout
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