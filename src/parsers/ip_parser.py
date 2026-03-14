"""Parser for IP address information."""

import logging
import re
from typing import List, Tuple, Dict, Optional
from functools import lru_cache

from src.models import IPAddress, NetworkOverview

logger = logging.getLogger(__name__)

# Паттерны для парсинга
COMMENT_PATTERN = re.compile(r'^\s*;;;\s*(.*)$')
ENTRY_START_PATTERN = re.compile(r'^\s*(\d+)\s+(?:([A*DX]+)\s+)?(.*)$')
CONTINUATION_PATTERN = re.compile(r'^\s{6,}|\t')


@lru_cache(maxsize=256)
def _parse_ip_data_cached(line: str) -> dict:
    """Кэшированная функция для парсинга строки IP адреса в словарь."""
    address_data = {}
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
        while i < n and line[i] != '=':
            i += 1
        key = line[key_start:i]

        if i >= n or line[i] != '=':
            break
        i += 1  # Skip '='

        # Skip whitespace after '='
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break

        # Find value (handle quoted strings)
        if line[i] == '"':
            value_start = i + 1
            i = value_start
            while i < n and line[i] != '"':
                i += 1
            value = line[value_start:i]
            i += 1  # Skip closing quote
        else:
            value_start = i
            while i < n and not line[i].isspace():
                i += 1
            value = line[value_start:i]

        address_data[key] = value

    return address_data


def _parse_ip_blocks(output: str) -> List[Dict[str, str]]:
    """
    Парсит вывод /ip address print detail в блоки с поддержкой комментариев.
    
    Формат RouterOS 7:
     1     ;;; Gateway for AdGuard container network
           address=192.168.3.2/24 network=192.168.3.0 interface=AdGuard
    
    Возвращает список словарей с данными IP-адресов включая комментарии.
    """
    addresses = []
    lines = output.split('\n')
    current_comment: Optional[str] = None
    current_data: Dict[str, str] = {}
    
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        
        # Пропускаем пустые строки и заголовки
        if not line.strip() or line.strip().startswith('Flags:'):
            i += 1
            continue
        
        # Проверяем комментарий
        comment_match = COMMENT_PATTERN.match(line.lstrip())
        if comment_match:
            current_comment = comment_match.group(1).strip()
            i += 1
            continue
        
        # Проверяем начало новой записи (цифра в начале)
        entry_match = ENTRY_START_PATTERN.match(line)
        if entry_match:
            # Сохраняем предыдущую запись
            if current_data:
                if current_comment and 'comment' not in current_data:
                    current_data['comment'] = current_comment
                addresses.append(current_data)
            
            # Начинаем новую запись
            current_comment = None
            current_data = {}
            
            # Парсим остаток строки после номера
            rest = entry_match.group(3) or ''
            if rest and '=' in rest:
                current_data = _parse_ip_data_cached(rest)
            i += 1
            continue
        
        # Проверяем продолжение (строка с отступом и key=value)
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_data is not None:
                data = _parse_ip_data_cached(line)
                current_data.update(data)
            i += 1
            continue
        
        # Старый формат: просто ищем address= в строке
        if 'address=' in line:
            data = _parse_ip_data_cached(line)
            if current_comment and 'comment' not in data:
                data['comment'] = current_comment
                current_comment = None
            addresses.append(data)
            i += 1
            continue
        
        i += 1
    
    # Сохраняем последнюю запись
    if current_data:
        if current_comment and 'comment' not in current_data:
            current_data['comment'] = current_comment
        addresses.append(current_data)
    
    return addresses


def parse_ip_address_results(ip_results: List) -> Tuple[List[IPAddress], NetworkOverview]:
    """Parse IP address results с поддержкой комментариев."""
    ip_addresses: List[IPAddress] = []
    overview = NetworkOverview()

    if not ip_results or ip_results[0].has_error:
        logger.warning("No IP address data available")
        return ip_addresses, overview

    # Собираем выводы всех команд IP address
    ip_output = ''
    for r in ip_results:
        if r.command.startswith('/ip address'):
            ip_output += r.stdout + '\n'
    
    # Парсим блоки с поддержкой комментариев
    address_blocks = _parse_ip_blocks(ip_output)
    
    for address_data in address_blocks:
        ip_addr = IPAddress()
        ip_addr.address = address_data.get('address', '')
        ip_addr.network = address_data.get('network', '')
        ip_addr.interface = address_data.get('interface', '')
        ip_addr.actual_interface = address_data.get('actual-interface', '')
        ip_addr.comment = address_data.get('comment', '')

        ip_addresses.append(ip_addr)
        logger.debug(f"Parsed IP: {ip_addr.address} on {ip_addr.interface}")

    overview.total_ip_addresses = len(ip_addresses)

    return ip_addresses, overview
