"""Parser for network interface statistics."""

import logging
import re
from typing import List, Tuple, Dict, Optional
from functools import lru_cache

from src.models import NetworkInterface, NetworkOverview

logger = logging.getLogger(__name__)

# Паттерны для парсинга
COMMENT_PATTERN = re.compile(r'^\s*;;;\s*(.*)$')
ENTRY_START_PATTERN = re.compile(r'^\s*(\d+)\s+(?:([A-Z]+)\s+)?(.*)$')
CONTINUATION_PATTERN = re.compile(r'^\s{6,}|\t')
STATS_LINE_PATTERN = re.compile(r'^\s*(\d+)\s+([RDLX]+)?\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)')


@lru_cache(maxsize=256)
def _parse_interface_data_cached(line: str) -> dict:
    """Кэшированная функция для парсинга строки интерфейса в словарь."""
    interface_data = {}
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

        interface_data[key] = value

    return interface_data


def _safe_int(value: str, default: int = 0) -> int:
    """Безопасное преобразование в целое число."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _safe_bool(value: str) -> bool:
    """Безопасное преобразование в булево значение."""
    return value == 'true'


def _parse_detail_blocks(output: str) -> Dict[str, dict]:
    """
    Парсит вывод /interface print detail в блоки по именам интерфейсов.
    
    Формат RouterOS:
     0  R  ether1   ;;; TrueNAS
      name=ether1 type=ether mtu=1500
      running=yes rx-byte=12345
      
    Возвращает dict: {interface_name: {parsed_data}}
    """
    interfaces: Dict[str, dict] = {}
    lines = output.split('\n')
    current_name: Optional[str] = None
    current_data: dict = {}
    current_comment: str = ''
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Пропускаем пустые строки и заголовки
        if not line.strip() or line.strip().startswith('Flags:'):
            i += 1
            continue
        
        # Проверяем комментарий
        comment_match = COMMENT_PATTERN.match(line)
        if comment_match:
            current_comment = comment_match.group(1).strip()
            i += 1
            continue
        
        # Проверяем начало новой записи (цифра в начале строки)
        entry_match = ENTRY_START_PATTERN.match(line)
        if entry_match:
            # Сохраняем предыдущую запись
            if current_name and current_data:
                if current_comment:
                    current_data['comment'] = current_comment
                interfaces[current_name] = current_data
            
            # Начинаем новую запись
            current_name = None
            current_data = {}
            current_comment = ''
            
            # Парсим остаток строки после номера
            rest = entry_match.group(3) or ''
            
            # Ищем name= в этой строке
            if 'name=' in rest:
                data = _parse_interface_data_cached(rest)
                if 'name' in data:
                    current_name = data['name']
                    current_data = data
            i += 1
            continue
        
        # Проверяем продолжение (строка с отступом)
        if CONTINUATION_PATTERN.match(line) or (line.startswith('  ') and '=' in line):
            # Это продолжение текущей записи
            if current_name is not None:
                data = _parse_interface_data_cached(line)
                current_data.update(data)
                # Если есть name, обновляем ключ
                if 'name' in data and not current_name:
                    current_name = data['name']
            i += 1
            continue
        
        # Строка с key=value без большого отступа (может быть частью записи)
        if '=' in line and current_name is not None:
            data = _parse_interface_data_cached(line)
            current_data.update(data)
            i += 1
            continue
        
        i += 1
    
    # Сохраняем последнюю запись
    if current_name and current_data:
        if current_comment:
            current_data['comment'] = current_comment
        interfaces[current_name] = current_data
    
    return interfaces


def _parse_stats_blocks(output: str) -> Dict[str, dict]:
    """
    Парсит вывод /interface print stats.
    
    Формат RouterOS (колоночный):
     0  R  ether1   2 360 330 144    572 441 255   3 205 419
     
    Или detail формат:
     0  name=ether1 rx-byte=123 tx-byte=456
    
    Возвращает dict: {interface_name: {rx_byte, tx_byte, rx_packet, tx_packet}}
    """
    stats: Dict[str, dict] = {}
    lines = output.split('\n')
    
    for line in lines:
        if not line.strip():
            continue
        
        # Пробуем парсить как key=value формат
        if 'name=' in line and ('rx-byte=' in line or 'tx-byte=' in line):
            data = _parse_interface_data_cached(line)
            if 'name' in data:
                name = data['name']
                stats[name] = {
                    'rx-byte': data.get('rx-byte', '0'),
                    'tx-byte': data.get('tx-byte', '0'),
                    'rx-packet': data.get('rx-packet', '0'),
                    'tx-packet': data.get('tx-packet', '0'),
                }
            continue
        
        # Пробуем парсить как колоночный формат
        stats_match = STATS_LINE_PATTERN.match(line)
        if stats_match:
            # Колоночный формат: номер, флаги, имя, rx, tx, и т.д.
            # Позиции колонок могут варьироваться, поэтому используем name= парсинг
            parts = line.split()
            if len(parts) >= 3:
                # Имя интерфейса обычно третье (после номера и флагов)
                name = parts[2]
                # Остальные колонки - статистика, но без явных меток сложно определить
                # Пропускаем колоночный формат, полагаемся на detail формат
                pass
    
    return stats


def parse_interface_stats(interface_results: List) -> Tuple[List[NetworkInterface], NetworkOverview]:
    """
    Parse interface statistics from command results.
    
    Поддерживает оба формата RouterOS:
    1. /interface print detail - многострочный key=value с комментариями ;;;
    2. /interface print stats - колоночный или key=value
    """
    interfaces: List[NetworkInterface] = []
    overview = NetworkOverview()

    if not interface_results or all(r.has_error for r in interface_results):
        logger.warning("No interface data available")
        return interfaces, overview

    # Собираем выводы всех команд интерфейсов
    detail_output = ''
    stats_output = ''
    
    for r in interface_results:
        if r.has_error:
            continue
        if '/interface print detail' in r.command or '/interface print' in r.command:
            detail_output += r.stdout + '\n'
        if '/interface print stats' in r.command:
            stats_output += r.stdout + '\n'
    
    # Если нет явного разделения, используем весь вывод как detail
    if not detail_output and stats_output:
        detail_output = stats_output
        stats_output = ''
    
    # Парсим detail блоки (основные данные + комментарии)
    detail_data = _parse_detail_blocks(detail_output) if detail_output else {}
    
    # Парсим stats блоки (статистика)
    stats_data = _parse_stats_blocks(stats_output) if stats_output else {}
    
    # Сливаем данные по имени интерфейса
    all_names = set(detail_data.keys()) | set(stats_data.keys())
    
    for name in sorted(all_names):
        data = {}
        if name in detail_data:
            data.update(detail_data[name])
        if name in stats_data:
            # Обновляем статистику из stats
            for key, value in stats_data[name].items():
                if key not in data or not data[key]:
                    data[key] = value
        
        if not data:
            continue
        
        interface = NetworkInterface()
        interface.name = data.get('name', name)
        interface.type = data.get('type', '')
        interface.mtu = _safe_int(data.get('mtu', '0'))
        interface.running = _safe_bool(data.get('running', 'false'))
        interface.disabled = _safe_bool(data.get('disabled', 'false'))
        interface.rx_byte = _safe_int(data.get('rx-byte', '0'))
        interface.tx_byte = _safe_int(data.get('tx-byte', '0'))
        interface.rx_packet = _safe_int(data.get('rx-packet', '0'))
        interface.tx_packet = _safe_int(data.get('tx-packet', '0'))
        interface.mac_address = data.get('mac-address', '')
        
        interfaces.append(interface)
        logger.debug(f"Parsed interface: {interface.name}, running: {interface.running}")

    overview.total_interfaces = len(interfaces)
    overview.active_interfaces = sum(1 for i in interfaces if i.running)

    return interfaces, overview
