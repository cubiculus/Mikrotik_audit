"""Parser for system logs, history and diagnostics."""

import logging
import re
from typing import List, Optional

from src.models import LogEntry, HistoryEntry

logger = logging.getLogger(__name__)


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
        
        # Find value - handle quoted strings with spaces
        if line[i] == '"':
            # Quoted value
            value_start = i + 1
            i = value_start
            while i < n and line[i] != '"':
                i += 1
            value = line[value_start:i]
            i += 1
        else:
            # Unquoted value - read until end or specific delimiters
            value_start = i
            while i < n and line[i] not in '\n':
                i += 1
            value = line[value_start:i].strip()
        
        data[key] = value
    
    return data


def parse_logs(results: List, count: int = 50) -> List[LogEntry]:
    """
    Parse system logs from /log print.
    
    Формат вывода RouterOS:
     0  12:30:45 system,info,account user admin logged in from 192.168.1.100
     1  12:30:40 firewall,info,drop in:ether1 out: (none), src-mac 00:11:22:33:44:55, proto TCP (SYN), 192.168.1.100:54321->10.0.0.1:80, len 60
    
    Или detail формат:
     0  time=12:30:45 topics=system,info,account message="user admin logged in"
    """
    entries = []
    
    if not results or results[0].has_error:
        logger.warning("No log data available")
        return entries
    
    output = results[0].stdout
    lines = output.split('\n')
    
    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue
        
        entry = LogEntry()
        
        # Пробуем парсить detail формат (time=, topics=, message=)
        if 'time=' in line or 'topics=' in line:
            data = _parse_key_value_line(line)
            entry.time = data.get('time', '')
            entry.topics = data.get('topics', '')
            entry.message = data.get('message', '')
            entry.prefix = data.get('prefix', '')
        else:
            # Парсим компактный формат
            # Формат: "0  12:30:45 topics message"
            match = re.match(r'^\s*\d+\s+(\d{2}:\d{2}:\d{2})\s+([^,]+),([^,]+),?(\S*)\s+(.*)$', line)
            if match:
                entry.time = match.group(1)
                entry.topics = f"{match.group(2)},{match.group(3)}"
                if match.group(4):
                    entry.topics += f",{match.group(4)}"
                entry.message = match.group(5)
            else:
                # Если не удалось распарсить, сохраняем как есть
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    entry.time = parts[1] if len(parts) > 1 else ''
                    entry.message = parts[2] if len(parts) > 2 else line
                elif len(parts) == 2:
                    entry.time = parts[1] if len(parts) > 1 else ''
                    entry.message = parts[1] if len(parts) > 1 else ''
        
        # Добавляем запись если есть данные
        if entry.time or entry.message:
            entries.append(entry)
            
            # Ограничиваем количество записей
            if len(entries) >= count:
                break
    
    return entries


def parse_firewall_logs(results: List) -> List[LogEntry]:
    """
    Parse firewall logs from /log print where topics~"firewall".
    
    Специализированный парсер для логов firewall.
    """
    entries = []
    
    if not results or results[0].has_error:
        logger.warning("No firewall log data available")
        return entries
    
    output = results[0].stdout
    lines = output.split('\n')
    
    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue
        
        entry = LogEntry()
        entry.topics = 'firewall'
        
        # Парсим логи firewall
        # Формат: "0  12:30:40 firewall,info,drop in:ether1 out: (none), src-mac ..."
        match = re.match(r'^\s*\d+\s+(\d{2}:\d{2}:\d{2})\s+firewall,(\w+),(\w+)\s+(.*)$', line)
        if match:
            entry.time = match.group(1)
            entry.prefix = f"{match.group(2)},{match.group(3)}"
            entry.message = match.group(4)
        else:
            # Пробуем detail формат
            data = _parse_key_value_line(line)
            entry.time = data.get('time', '')
            entry.message = data.get('message', '')
            if data.get('topics', ''):
                entry.topics = data.get('topics', '')
        
        if entry.time or entry.message:
            entries.append(entry)
    
    return entries


def parse_history(results: List) -> List[HistoryEntry]:
    """
    Parse system history from /system history print.
    
    Формат вывода RouterOS:
     0  12:30:45 by=admin add /ip address address=192.168.1.1/24 interface=ether1
     1  12:25:30 by=admin remove /ip firewall filter numbers=5
     2  12:20:15 by=admin set /interface ether name=ether1
    
    Или detail формат:
     0  time=12:30:45 action=add cmd="/ip address add address=192.168.1.1/24" by=admin
    """
    entries = []
    
    if not results or results[0].has_error:
        logger.warning("No history data available")
        return entries
    
    output = results[0].stdout
    lines = output.split('\n')
    
    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue
        
        entry = HistoryEntry()
        
        # Пробуем парсить detail формат
        if 'time=' in line or 'action=' in line:
            data = _parse_key_value_line(line)
            entry.time = data.get('time', '')
            entry.action = data.get('action', '')
            entry.by = data.get('by', '')
            entry.cmd = data.get('cmd', '')
        else:
            # Парсим компактный формат
            # Формат: "0  12:30:45 by=admin action /path cmd"
            match = re.match(r'^\s*\d+\s+(\d{2}:\d{2}:\d{2})\s+by=(\S+)\s+(\w+)\s+(.*)$', line)
            if match:
                entry.time = match.group(1)
                entry.by = match.group(2)
                entry.action = match.group(3)
                entry.cmd = match.group(4)
            else:
                # Если не удалось распарсить, сохраняем как есть
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    entry.time = parts[1] if len(parts) > 1 else ''
                    entry.action = parts[2] if len(parts) > 2 else ''
                    entry.cmd = parts[3] if len(parts) > 3 else ''
        
        # Добавляем запись если есть данные
        if entry.time or entry.cmd:
            entries.append(entry)
    
    return entries


def parse_ping_results(results: List) -> dict:
    """
    Parse ping test results.
    
    Формат вывода RouterOS:
     SEQ HOST SIZE TTL TIME STATUS
       0 8.8.8.8 56 116 2ms
       1 8.8.8.8 56 116 3ms
       2 8.8.8.8 56 116 2ms
       sent=3 received=3 lost=0 avg-rtt=2ms
    """
    ping_result = {
        'target': '',
        'sent': 0,
        'received': 0,
        'lost': 0,
        'loss_percent': 0.0,
        'avg_rtt': '',
        'min_rtt': '',
        'max_rtt': '',
        'results': [],
    }
    
    if not results or results[0].has_error:
        logger.warning("No ping data available")
        return ping_result
    
    output = results[0].stdout
    
    # Извлекаем target из команды
    for r in results:
        if '/ping' in r.command:
            match = re.search(r'/ping\s+(\S+)', r.command)
            if match:
                ping_result['target'] = match.group(1)
            break
    
    # Парсим результаты
    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Ищем статистику
        if 'sent=' in line and 'received=' in line:
            data = _parse_key_value_line(line)
            try:
                ping_result['sent'] = int(data.get('sent', '0'))
                ping_result['received'] = int(data.get('received', '0'))
                ping_result['lost'] = int(data.get('lost', '0'))
                
                if ping_result['sent'] > 0:
                    ping_result['loss_percent'] = (ping_result['lost'] / ping_result['sent']) * 100
                
                ping_result['avg_rtt'] = data.get('avg_rtt', '') or data.get('avg-rtt', '')
                ping_result['min_rtt'] = data.get('min_rtt', '') or data.get('min-rtt', '')
                ping_result['max_rtt'] = data.get('max_rtt', '') or data.get('max-rtt', '')
            except ValueError:
                pass
        else:
            # Парсим отдельные пинги
            # Формат: "0 8.8.8.8 56 116 2ms" или "0 8.8.8.8 56 116 2ms ttl-unreachable"
            parts = line.split()
            if len(parts) >= 5 and parts[0].isdigit():
                ping_entry = {
                    'seq': int(parts[0]),
                    'host': parts[1] if len(parts) > 1 else '',
                    'size': int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                    'ttl': int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0,
                    'time': parts[4] if len(parts) > 4 else '',
                    'status': ' '.join(parts[5:]) if len(parts) > 5 else 'ok',
                }
                ping_result['results'].append(ping_entry)
    
    return ping_result
