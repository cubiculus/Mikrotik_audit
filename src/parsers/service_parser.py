"""Parser for services, users, certificates, scripts and scheduler."""

import logging
import re
from typing import List, Optional
from functools import lru_cache

from src.models import Service, SSHSession, Certificate, Script, Scheduler, User

logger = logging.getLogger(__name__)


@lru_cache(maxsize=128)
def _parse_key_value_line(line: str) -> dict:
    """Parse key=value or key: value line into dictionary."""
    data = {}
    i = 0
    n = len(line)
    
    while i < n:
        # Skip whitespace
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break
        
        # Find key
        key_start = i
        while i < n and line[i] not in '=:':
            i += 1
        
        if i >= n:
            break
        
        key = line[key_start:i].strip().lower().replace('-', '_')
        
        # Skip separator
        sep = line[i]
        i += 1
        
        # Skip whitespace
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break
        
        # Find value
        if line[i] == '"':
            # Quoted value
            value_start = i + 1
            i = value_start
            while i < n and line[i] != '"':
                i += 1
            value = line[value_start:i]
            i += 1
        else:
            # Unquoted value
            value_start = i
            while i < n and not line[i].isspace():
                i += 1
            value = line[value_start:i]
        
        data[key] = value
    
    return data


def parse_ip_service(results: List) -> List[Service]:
    """
    Parse IP service information from /ip service print detail.
    
    Формат вывода RouterOS:
     0  name=telnet port=23 disabled=no
     1  name=ftp port=21 disabled=yes
     2  name=ssh port=22 disabled=no tls-required=yes address=192.168.1.0/24
    """
    services = []
    
    if not results or results[0].has_error:
        logger.warning("No IP service data available")
        return services
    
    output = results[0].stdout
    
    # Парсинг многострочного формата
    current_service: Optional[dict] = None
    lines = output.split('\n')
    
    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue
        
        # Проверяем начало новой записи
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущий сервис
            if current_service:
                services.append(_create_service(current_service))
            
            # Начинаем новый сервис
            current_service = {}
            rest = entry_match.group(3) or ''
            
            if '=' in rest:
                current_service.update(_parse_key_value_line(rest))
            continue
        
        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_service is not None:
                current_service.update(_parse_key_value_line(line))
            continue
    
    # Сохраняем последний сервис
    if current_service:
        services.append(_create_service(current_service))
    
    return services


def _create_service(data: dict) -> Service:
    """Create Service object from dictionary."""
    service = Service()
    service.name = data.get('name', '')
    
    try:
        service.port = int(data.get('port', 0))
    except ValueError:
        pass
    
    service.disabled = data.get('disabled', 'no') in ('yes', 'true')
    service.tls_required = data.get('tls_required', 'no') in ('yes', 'true')
    service.address = data.get('address', '')
    service.comment = data.get('comment', '')
    
    return service


def parse_ssh_sessions(results: List) -> List[SSHSession]:
    """
    Parse active SSH sessions from /ip ssh print detail.
    
    Формат вывода RouterOS:
     dynamic-connection: 0  user=admin remote=192.168.1.100:54321 connected-since=2h30m
    """
    sessions = []
    
    if not results or results[0].has_error:
        logger.warning("No SSH session data available")
        return sessions
    
    output = results[0].stdout
    
    # Ищем строки с dynamic-connection или active connections
    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        # Проверяем наличие remote= (признак активной сессии)
        if 'remote=' in line or 'user=' in line:
            data = _parse_key_value_line(line)
            
            session = SSHSession()
            session.user = data.get('user', '')
            
            # Parse remote address:port
            remote = data.get('remote', '')
            if ':' in remote:
                parts = remote.rsplit(':', 1)
                session.remote_address = parts[0]
                try:
                    session.remote_port = int(parts[1])
                except ValueError:
                    pass
            else:
                session.remote_address = remote
            
            session.connected_since = data.get('connected_since', '') or data.get('connected-since', '')
            session.encoding = data.get('encoding', '')
            session.client = data.get('client', '')
            
            if session.user or session.remote_address:
                sessions.append(session)
    
    return sessions


def parse_users(results: List) -> List[User]:
    """
    Parse user information from /user print detail.
    
    Формат вывода RouterOS:
     0  name=admin group=full disabled=no
        address=0.0.0.0/0 netmask=0.0.0.0
        last-logged-in=2026-03-14 17:40:13
    """
    users = []
    
    if not results or results[0].has_error:
        logger.warning("No user data available")
        return users
    
    output = results[0].stdout
    
    # Парсинг многострочного формата
    current_user: Optional[dict] = None
    lines = output.split('\n')
    
    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue
        
        # Проверяем начало новой записи
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущего пользователя
            if current_user:
                users.append(_create_user(current_user))
            
            # Начинаем нового пользователя
            current_user = {}
            rest = entry_match.group(3) or ''
            
            if '=' in rest:
                current_user.update(_parse_key_value_line(rest))
            continue
        
        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_user is not None:
                current_user.update(_parse_key_value_line(line))
            continue
    
    # Сохраняем последнего пользователя
    if current_user:
        users.append(_create_user(current_user))
    
    return users


def _create_user(data: dict) -> User:
    """Create User object from dictionary."""
    user = User()
    user.name = data.get('name', '')
    user.group = data.get('group', '')
    user.address = data.get('address', '')
    user.netmask = data.get('netmask', '')
    user.disabled = data.get('disabled', 'no') in ('yes', 'true')
    user.expired = data.get('expired', 'no') in ('yes', 'true')
    user.last_logged_in = data.get('last_logged_in', '') or data.get('last-logged-in', '')
    user.comment = data.get('comment', '')
    
    return user


def parse_certificates(results: List) -> List[Certificate]:
    """
    Parse certificate information from /system certificate print detail.
    
    Формат вывода RouterOS:
     0  name=cert1 common-name=example.com
        subject=C=LV,L=Riga,CN=example.com
        issuer=C=LV,O=Example,CN=Example CA
        serial-number=1234567890
        valid-from=Jan/01/2024
        valid-until=Jan/01/2025
        key-type=rsa
        key-size=2048
    """
    certificates = []
    
    if not results or results[0].has_error:
        logger.warning("No certificate data available")
        return certificates
    
    output = results[0].stdout
    
    # Парсинг многострочного формата
    current_cert: Optional[dict] = None
    lines = output.split('\n')
    
    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue
        
        # Проверяем начало новой записи
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущий сертификат
            if current_cert:
                certificates.append(_create_certificate(current_cert))
            
            # Начинаем новый сертификат
            current_cert = {}
            rest = entry_match.group(3) or ''
            
            if '=' in rest:
                current_cert.update(_parse_key_value_line(rest))
            continue
        
        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_cert is not None:
                current_cert.update(_parse_key_value_line(line))
            continue
    
    # Сохраняем последний сертификат
    if current_cert:
        certificates.append(_create_certificate(current_cert))
    
    return certificates


def _create_certificate(data: dict) -> Certificate:
    """Create Certificate object from dictionary."""
    cert = Certificate()
    cert.name = data.get('name', '')
    cert.common_name = data.get('common_name', '') or data.get('common-name', '')
    cert.subject = data.get('subject', '')
    cert.issuer = data.get('issuer', '')
    cert.serial_number = data.get('serial_number', '') or data.get('serial-number', '')
    cert.valid_from = data.get('valid_from', '') or data.get('valid-from', '')
    cert.valid_until = data.get('valid_until', '') or data.get('valid-until', '')
    cert.key_type = data.get('key_type', '') or data.get('key-type', '')
    cert.fingerprint = data.get('fingerprint', '')
    cert.comment = data.get('comment', '')
    
    try:
        cert.key_size = int(data.get('key_size', '') or data.get('key-size', '0'))
    except ValueError:
        pass
    
    # Check if expired (simple check based on valid-until)
    # Full check would require date parsing
    cert.expired = data.get('expired', 'no') in ('yes', 'true')
    cert.revoked = data.get('revoked', 'no') in ('yes', 'true')
    cert.trusted = data.get('trusted', 'no') in ('yes', 'true')
    
    return cert


def parse_scripts(results: List) -> List[Script]:
    """
    Parse script information from /system script print detail.
    
    Формат вывода RouterOS:
     0  name=script1 owner=admin policy=ftp,reboot,read,write,policy,test
        dont-require-permissions=no
        last-modified=Jan/01/2024 12:00:00
        source=/log info "Hello"
    """
    scripts = []
    
    if not results or results[0].has_error:
        logger.warning("No script data available")
        return scripts
    
    output = results[0].stdout
    
    # Парсинг многострочного формата
    current_script: Optional[dict] = None
    lines = output.split('\n')
    
    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue
        
        # Проверяем начало новой записи
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущий скрипт
            if current_script:
                scripts.append(_create_script(current_script))
            
            # Начинаем новый скрипт
            current_script = {}
            rest = entry_match.group(3) or ''
            
            if '=' in rest:
                current_script.update(_parse_key_value_line(rest))
            continue
        
        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_script is not None:
                current_script.update(_parse_key_value_line(line))
            continue
    
    # Сохраняем последний скрипт
    if current_script:
        scripts.append(_create_script(current_script))
    
    return scripts


def _create_script(data: dict) -> Script:
    """Create Script object from dictionary."""
    script = Script()
    script.name = data.get('name', '')
    script.owner = data.get('owner', '')
    
    # Parse policy
    policy_str = data.get('policy', '')
    if policy_str:
        script.policy = [p.strip() for p in policy_str.split(',')]
    
    script.dont_require_permissions = data.get('dont_require_permissions', 'no') in ('yes', 'true')
    script.last_modified = data.get('last_modified', '') or data.get('last-modified', '')
    script.source = data.get('source', '')
    
    return script


def parse_scheduler(results: List) -> List[Scheduler]:
    """
    Parse scheduler information from /system scheduler print detail.
    
    Формат вывода RouterOS:
     0  name=scheduler1 start-date=jan/01/2024 start-time=12:00:00
        interval=1d run-count=5 last-run=mar/14/2026 10:00:00
        next-run=mar/15/2026 10:00:00 on-event=script1
        disabled=no
    """
    schedulers = []
    
    if not results or results[0].has_error:
        logger.warning("No scheduler data available")
        return schedulers
    
    output = results[0].stdout
    
    # Парсинг многострочного формата
    current_scheduler: Optional[dict] = None
    lines = output.split('\n')
    
    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue
        
        # Проверяем начало новой записи
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущий планировщик
            if current_scheduler:
                schedulers.append(_create_scheduler(current_scheduler))
            
            # Начинаем новый планировщик
            current_scheduler = {}
            rest = entry_match.group(3) or ''
            
            if '=' in rest:
                current_scheduler.update(_parse_key_value_line(rest))
            continue
        
        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_scheduler is not None:
                current_scheduler.update(_parse_key_value_line(line))
            continue
    
    # Сохраняем последний планировщик
    if current_scheduler:
        schedulers.append(_create_scheduler(current_scheduler))
    
    return schedulers


def _create_scheduler(data: dict) -> Scheduler:
    """Create Scheduler object from dictionary."""
    scheduler = Scheduler()
    scheduler.name = data.get('name', '')
    scheduler.start_date = data.get('start_date', '') or data.get('start-date', '')
    scheduler.start_time = data.get('start_time', '') or data.get('start-time', '')
    scheduler.interval = data.get('interval', '')
    scheduler.on_event = data.get('on_event', '') or data.get('on-event', '')
    scheduler.script = data.get('script', '')
    scheduler.disabled = data.get('disabled', 'no') in ('yes', 'true')
    scheduler.comment = data.get('comment', '')
    
    try:
        scheduler.run_count = int(data.get('run_count', '') or data.get('run-count', '0'))
    except ValueError:
        pass
    
    scheduler.last_run = data.get('last_run', '') or data.get('last-run', '')
    scheduler.next_run = data.get('next_run', '') or data.get('next-run', '')
    
    return scheduler
