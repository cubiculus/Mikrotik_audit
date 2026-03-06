# Configuration file for MikroTik Audit
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from enum import Enum
import os

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=".env")
except ImportError:
    pass

class AuditLevel(str, Enum):
    BASIC = "Basic"
    STANDARD = "Standard"
    COMPREHENSIVE = "Comprehensive"

class RouterConfig(BaseModel):
    router_ip: str = Field(default_factory=lambda: os.getenv("MIKROTIK_IP", "192.168.1.1"))
    ssh_port: int = Field(default_factory=lambda: int(os.getenv("MIKROTIK_PORT", 22)))
    ssh_user: str = Field(default_factory=lambda: os.getenv("MIKROTIK_USER", "admin"))
    ssh_pass: str = Field(default_factory=lambda: os.getenv("MIKROTIK_PASSWORD", ""))
    ssh_key_file: Optional[str] = Field(default_factory=lambda: os.getenv("MIKROTIK_SSH_KEY_FILE"))  # Путь к приватному SSH-ключу
    ssh_key_passphrase: Optional[str] = Field(default_factory=lambda: os.getenv("MIKROTIK_SSH_KEY_PASSPHRASE"))  # Пароль для ключа
    connect_timeout: int = 30
    command_timeout: int = 120
    max_retries: int = 3

    @field_validator('ssh_port')
    @classmethod
    def validate_ssh_port(cls, v):
        """Validate SSH port is in valid range (1-65535)."""
        if not 1 <= v <= 65535:
            raise ValueError(f"SSH port must be between 1 and 65535, got {v}")
        return v

    @field_validator('connect_timeout', 'command_timeout', 'max_retries')
    @classmethod
    def validate_positive_integers(cls, v, field):
        """Validate timeout and retry values are positive."""
        if v <= 0:
            raise ValueError(f"{field.field_name} must be positive, got {v}")
        return v

class AuditConfig(BaseModel):
    router: RouterConfig = Field(default_factory=RouterConfig)
    audit_level: AuditLevel = Field(default=AuditLevel.STANDARD)
    skip_security_check: bool = False
    output_dir: Optional[str] = None
    max_workers: int = 5
    redact_sensitive: bool = False  # Маскирование чувствительных данных (PPP-секреты, пароли, серийный номер)

class CommandResult(BaseModel):
    index: int
    command: str
    exit_status: int = 0
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    has_error: bool = False
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    attempt: int = 1

class SecurityIssue(BaseModel):
    severity: str
    category: str
    finding: str = ""
    description: str = ""
    recommendation: str
    command: str = ""
    
    def __init__(self, **data):
        if 'finding' not in data and 'description' in data:
            data['finding'] = data['description']
        elif 'description' not in data and 'finding' in data:
            data['description'] = data['finding']
        super().__init__(**data)

class RouterInfo(BaseModel):
    identity: str = ""
    model: str = ""
    version: str = ""
    ip: str = ""
    # serial_number намеренно исключён (требования безопасности)
    uptime: Optional[str] = None
    cpu_count: int = 1
    board_name: Optional[str] = None
    architecture: Optional[str] = None

class BackupResult(BaseModel):
    status: str = "failed"
    timestamp: str = ""
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    error_message: Optional[str] = None
    local_path: Optional[str] = None
    download_error: Optional[str] = None


def redact_sensitive_data(text: str) -> str:
    """
    Маскирует чувствительные данные в тексте:
    - Серийные номера
    - Пароли PPP-секретов
    - Пароли Hotspot пользователей
    - IP-адреса (частично)
    """
    import re
    
    if not text:
        return text
    
    result = text
    
    # Маскирование серийных номеров (формат MikroTik: 8 символов буквы/цифры)
    result = re.sub(r'(?i)(serial[-_]?number|serial):\s*([A-Z0-9]{8})', r'\1: [REDACTED]', result)
    
    # Маскирование паролей PPP secrets
    result = re.sub(r'(?i)(password|secret)[-_]?ppp[^:]*:\s*(\S+)', r'\1: [REDACTED]', result)
    result = re.sub(r'(?i)ppp\s+secret.*?(password|secret)=(\S+)', r'[PP SECRET REDACTED]', result, flags=re.IGNORECASE)
    
    # Маскирование паролей Hotspot пользователей
    result = re.sub(r'(?i)(hotspot\s+user).*?(password|pwd)=(\S+)', r'\1 [PASSWORD REDACTED]', result, flags=re.IGNORECASE)
    
    # Маскирование IP-адресов (последний октет)
    result = re.sub(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b', r'\1***', result)
    
    return result
