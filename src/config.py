# Configuration file for MikroTik Audit
from typing import Any, List, Optional
from pydantic import BaseModel, Field, field_validator
from enum import Enum
import os
import ipaddress

# Note: load_dotenv() is called in cli.py with absolute path to project root

class AuditLevel(str, Enum):
    BASIC = "Basic"
    STANDARD = "Standard"
    COMPREHENSIVE = "Comprehensive"

class RouterConfig(BaseModel):
    router_ip: str = Field(default_factory=lambda: os.getenv("MIKROTIK_IP", "192.168.100.1"))
    ssh_port: int = Field(default_factory=lambda: int(os.getenv("MIKROTIK_PORT", 22)))
    ssh_user: str = Field(default_factory=lambda: os.getenv("MIKROTIK_USER", "admin"))
    ssh_pass: str = Field(default_factory=lambda: os.getenv("MIKROTIK_PASSWORD", ""))
    ssh_key_file: Optional[str] = Field(default_factory=lambda: os.getenv("MIKROTIK_SSH_KEY_FILE"))  # Путь к приватному SSH-ключу
    ssh_key_passphrase: Optional[str] = Field(default_factory=lambda: os.getenv("MIKROTIK_SSH_KEY_PASSPHRASE"))  # Пароль для ключа
    connect_timeout: int = 30
    command_timeout: int = 120
    timeout_per_command: Optional[int] = None  # Optional per-command timeout (overrides command_timeout)
    max_retries: int = 3

    @field_validator('router_ip')
    @classmethod
    def validate_router_ip(cls, v: str) -> str:
        """Validate router IP address is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(f"Invalid router IP address: {v}. Error: {e}")
        return v

    @field_validator('ssh_port')
    @classmethod
    def validate_ssh_port(cls, v: int) -> int:
        """Validate SSH port is in valid range (1-65535)."""
        if not 1 <= v <= 65535:
            raise ValueError(f"SSH port must be between 1 and 65535, got {v}")
        return v

    @field_validator('connect_timeout', 'command_timeout', 'timeout_per_command', 'max_retries')
    @classmethod
    def validate_positive_integers(cls, v: Optional[int], field) -> Optional[int]:
        """Validate timeout and retry values are positive."""
        if v is not None and v <= 0:
            raise ValueError(f"{field.field_name} must be positive, got {v}")
        return v

class AuditConfig(BaseModel):
    router: RouterConfig = Field(default_factory=RouterConfig)
    audit_level: AuditLevel = Field(default=AuditLevel.STANDARD)
    audit_profile: Optional[str] = None  # Thematic audit profile: wifi, protocols, system, security, network, containers
    skip_security_check: bool = False
    output_dir: Optional[str] = None
    max_workers: int = 0  # 0 = auto-calculate optimal workers based on command count
    redact_sensitive: bool = False  # Маскирование чувствительных данных (PPP-секреты, пароли, серийный номер)
    output_formats: list = Field(default_factory=lambda: ["html", "json"])  # Report formats to generate
    enable_cve_check: bool = True  # Check RouterOS version against CVE database
    enable_live_cve_lookup: bool = True  # Use live NIST NVD API for CVE lookup (with 24h caching)
    show_progress_bar: bool = True  # Show tqdm progress bar instead of verbose logs

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
    fix_commands: List[str] = Field(default_factory=list)  # Команды для исправления проблемы

    def __init__(self, **data: Any) -> None:
        """Initialize SecurityIssue with backward compatibility for finding/description fields."""
        # Handle backward compatibility for finding/description fields
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
    Mask sensitive data in text:
    - Serial numbers
    - PPP secrets passwords
    - Hotspot user passwords
    - Public IP addresses (partially)
    - MAC addresses
    - User login names
    - Host names from DHCP
    - Client IDs
    - Last logged-in timestamps
    - Time zone city names

    Internal IP addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x) are NOT masked
    as they are not considered sensitive for audit purposes.
    """
    import re

    if not text:
        return text

    result = text

    # Mask serial numbers (MikroTik format: 8 alphanumeric chars)
    result = re.sub(r'(?i)(serial[-_]?number|serial):\s*([A-Z0-9]{8})', r'\1: [REDACTED]', result)

    # Mask PPP secrets passwords
    result = re.sub(r'(?i)(password|secret)[-_]?ppp[^:]*:\s*\S+', r'\1: [REDACTED]', result)
    result = re.sub(r'(?i)ppp[\s\-_]+secret[\s\-_]*=[\s\-_]*\S+', r'[PP SECRET REDACTED]', result, flags=re.IGNORECASE)

    # Mask Hotspot user passwords
    result = re.sub(r'(?i)hotspot[\s\-_]+user[\s\-_]*=[\s\-_]*\S+', r'[PASSWORD REDACTED]', result, flags=re.IGNORECASE)

    # Mask password fields (all variations)
    result = re.sub(r'password[\s\-_:]*=[\s\-_:]*[^=\s]+', 'password=[REDACTED]', result, flags=re.IGNORECASE)
    result = re.sub(r'password[\s\-_:]*:[\s\-_:]*\S+', 'password: [REDACTED]', result, flags=re.IGNORECASE)
    result = re.sub(r'pwd[\s\-_:]*=[\s\-_:]*[^=\s]+', 'pwd=[REDACTED]', result, flags=re.IGNORECASE)
    result = re.sub(r'pwd[\s\-_:]*:[\s\-_:]*\S+', 'pwd: [REDACTED]', result, flags=re.IGNORECASE)

    # Mask MAC addresses (globally unique device identifiers)
    result = re.sub(r'\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b', '[MAC REDACTED]', result)

    # Mask user login names from /user print
    result = re.sub(r'name="([^"]+)"(?=.*group=)', r'name="[USER REDACTED]"', result)
    result = re.sub(r'name=([^\s,]+)(?=.*group=)', r'name=[USER REDACTED]', result)

    # Mask host names from DHCP leases
    result = re.sub(r'host-name="([^"]+)"', r'host-name="[HOST REDACTED]"', result)
    result = re.sub(r'host-name=([^\s,]+)', r'host-name=[HOST REDACTED]', result)

    # Mask client IDs (hardware fingerprints)
    result = re.sub(r'client-id="([^"]+)"', r'client-id="[ID REDACTED]"', result)
    result = re.sub(r'client-id=([^\s,]+)', r'client-id=[ID REDACTED]', result)

    # Mask last logged-in timestamps (activity patterns)
    result = re.sub(r'last-logged-in=\S+', r'last-logged-in=[REDACTED]', result)

    # Mask time zone city (keep region only)
    # Europe/Moscow -> Europe/[REDACTED]
    result = re.sub(r'(time-zone[-_]?name:\s*\w+)/(\w+)', r'\1/[REDACTED]', result)
    result = re.sub(r'(time-zone[-_]?name=)(\w+)/(\w+)', r'\1\2/[REDACTED]', result)

    # Mask container names (reveal installed software)
    result = re.sub(r'name="([^"]+)"(?=\s+remote-image=)', r'name="[CONTAINER REDACTED]"', result)
    result = re.sub(r'hostname="([^"]+)"', r'hostname="[HOST REDACTED]"', result)

    # Mask email addresses (in registry usernames, etc.)
    result = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL REDACTED]', result)

    # Mask WireGuard public keys (cryptographic identifiers)
    result = re.sub(r'public-key="[^"]+"', r'public-key="[WG KEY REDACTED]"', result)
    result = re.sub(r'public-key=([^\s,]+)', r'public-key=[WG KEY REDACTED]', result)

    # Mask endpoint addresses (reveal external services)
    result = re.sub(r'endpoint-address="?([^"\s]+)"?', r'endpoint-address="[ENDPOINT REDACTED]"', result)

    # Mask dynamic connection info (active SSH sessions)
    result = re.sub(r'remote=(\d+\.\d+\.\d+\.\d+:\d+)', r'remote=[CONNECTION REDACTED]', result)
    result = re.sub(r'connected-since=\S+', r'connected-since=[TIME REDACTED]', result)

    # Mask container MAC addresses
    result = re.sub(r'container-mac-address=([0-9A-Fa-f:]+)', r'container-mac-address=[MAC REDACTED]', result)

    # Mask Docker image tags (reveal software versions)
    result = re.sub(r'tag="([^"]+)"', r'tag="[TAG REDACTED]"', result)
    result = re.sub(r'remote-image="([^"]+)"', r'remote-image="[IMAGE REDACTED]"', result)

    # Mask file paths (reveal directory structure)
    result = re.sub(r'root-dir=(/[^\s,]+)', r'root-dir=[PATH REDACTED]', result)
    result = re.sub(r'layer-dir=(/[^\s,]+)', r'layer-dir=[PATH REDACTED]', result)
    result = re.sub(r'mount=([^\s,]+:[^\s,]+)', r'mount=[MOUNT REDACTED]', result)

    # Mask image IDs and layer IDs (Docker internals)
    result = re.sub(r'image-id="[^"]+"', r'image-id="[ID REDACTED]"', result)
    result = re.sub(r'layers=([^\s,]+)', r'layers=[LAYERS REDACTED]', result)

    # Mask ONLY public IP addresses (not private ranges)
    # Private IP ranges to exclude:
    # - 10.0.0.0/8
    # - 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
    # - 192.168.0.0/16
    # - 127.0.0.0/8 (loopback)
    # - 169.254.0.0/16 (link-local)
    # - 224.0.0.0/4 (multicast)

    def _is_private_ip(match: Any) -> bool:
        """Check if matched IP is in private range."""
        ip = match.group(0)
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return False

            first, second, third, fourth = octets

            # 10.0.0.0/8
            if first == 10:
                return True

            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True

            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True

            # 127.0.0.0/8 (loopback)
            if first == 127:
                return True

            # 169.254.0.0/16 (link-local)
            if first == 169 and second == 254:
                return True

            # 224.0.0.0/4 (multicast)
            if first >= 224:
                return True

            return False
        except (ValueError, IndexError):
            return False

    # Match IP addresses and filter out private ones
    def _mask_public_ip(match: Any) -> str:
        """Mask the IP if it's public, keep it if private."""
        if _is_private_ip(match):
            return match.group(0)  # Keep private IPs unchanged
        # Mask public IPs (replace last octet)
        return match.group(1) + '***'

    result = re.sub(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b', _mask_public_ip, result)

    return result
