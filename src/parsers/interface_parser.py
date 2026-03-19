"""Parser for network interface statistics."""

import logging
import re
from typing import List, Tuple, Dict, Optional

from src.models import NetworkInterface, NetworkOverview
from src.parsers.utils import parse_key_value_line

logger = logging.getLogger(__name__)

# Паттерны для парсинга
COMMENT_PATTERN = re.compile(r'^\s*;;;\s*(.*)$')
# Формат: "*1  R  name=ether1" или " 0  R  name=ether1"
ENTRY_START_PATTERN = re.compile(r'^\s*(\*?\d+)\s+(?:([A-Z]+)\s+)?(.*)$')
CONTINUATION_PATTERN = re.compile(r'^\s{6,}|\t')


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
     *1  R  ;;; TrueNAS
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
        stripped = line.strip()

        # Пропускаем пустые строки и заголовки
        if not stripped or stripped.startswith('Flags:') or stripped.startswith('Columns:'):
            i += 1
            continue

        # Проверяем комментарий (отдельная строка с ;;;)
        comment_match = COMMENT_PATTERN.match(line)
        if comment_match:
            current_comment = comment_match.group(1).strip()
            i += 1
            continue

        # Проверяем начало новой записи (цифра или *цифра в начале строки)
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

            # Проверяем если комментарий в той же строке что и номер
            if rest.startswith(';;;'):
                current_comment = rest[3:].strip()
                # Комментарий в начале строки - name= будет на следующей строке
                i += 1
                continue

            # Ищем name= в этой строке
            if 'name=' in rest:
                data = parse_key_value_line(rest)
                if 'name' in data:
                    current_name = data['name']
                    current_data = data
            i += 1
            continue

        # Проверяем продолжение (строка с отступом 4+ пробелов или tab)
        if (line.startswith('      ') or line.startswith('\t')) and '=' in line:
            # Это продолжение текущей записи или начало новой если current_name ещё не установлен
            data = parse_key_value_line(line)
            if 'name' in data:
                current_name = data['name']
                current_data = data
            elif current_name is not None:
                current_data.update(data)
            i += 1
            continue

        # Строка с меньшим отступом но с key=value (может быть частью записи)
        if line.startswith('  ') and '=' in line and current_name is not None:
            data = parse_key_value_line(line)
            current_data.update(data)
            if 'name' in data and not current_name:
                current_name = data['name']
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

    Формат RouterOS v7 (колоночный):
    Flags: X - DISABLED; R - RUNNING; S - SLAVE
    Columns: NAME, RX-BYTE, TX-BYTE, RX-PACKET
     #     NAME                         RX-BYTE        TX-BYTE  RX-PACKET
     0  R  ether1                 2 360 330 144    572 441 255  3 205 419
     5  RS ADGUARD-TUN               36 552 256     47 124 055    389 838

    Или detail формат с key=value:
     *1  R  name=ether1 rx-byte=1000 tx-byte=2000

    Возвращает dict: {interface_name: {rx_byte, tx_byte, rx_packet, tx_packet}}
    """
    stats: Dict[str, dict] = {}
    lines = output.split('\n')

    # Определяем формат: колоночный или key=value
    is_column_format = False
    for line in lines:
        if 'Columns:' in line and 'RX-BYTE' in line:
            is_column_format = True
            break
        if 'name=' in line and 'rx-byte=' in line:
            break

    if is_column_format:
        # Парсим колоночный формат
        stats = _parse_column_stats(lines)
    else:
        # Парсим key=value формат (RouterOS v7 detail)
        for line in lines:
            if not line.strip():
                continue

            # Пробуем парсить как key=value формат (RouterOS v7)
            if 'name=' in line:
                # Удаляем префикс типа "*1  R  " если есть
                entry_match = ENTRY_START_PATTERN.match(line)
                if entry_match:
                    rest = entry_match.group(3) or ''
                    if 'name=' in rest:
                        data = parse_key_value_line(rest)
                        if 'name' in data:
                            name = data['name']
                            stats[name] = {
                                'rx-byte': data.get('rx_byte', '0'),
                                'tx-byte': data.get('tx_byte', '0'),
                                'rx-packet': data.get('rx_packet', '0'),
                                'tx-packet': data.get('tx_packet', '0'),
                            }
                elif 'name=' in line:
                    # Просто строка с key=value
                    data = parse_key_value_line(line)
                    if 'name' in data:
                        name = data['name']
                        stats[name] = {
                            'rx-byte': data.get('rx_byte', '0'),
                            'tx-byte': data.get('tx_byte', '0'),
                            'rx-packet': data.get('rx_packet', '0'),
                            'tx-packet': data.get('tx_packet', '0'),
                        }

    return stats


def _parse_column_stats(lines: List[str]) -> Dict[str, dict]:
    """
    Парсит колоночный формат статистики интерфейсов.

    Формат:
     #     NAME                         RX-BYTE        TX-BYTE  RX-PACKET
     0  R  ether1                 2 360 330 144    572 441 255  3 205 419
     5  RS ADGUARD-TUN               36 552 256     47 124 055    389 838
    """
    stats = {}
    current_comment = ''

    for line in lines:
        stripped = line.strip()

        # Пропускаем пустые строки, заголовки, flags
        if not stripped or stripped.startswith('Flags:') or stripped.startswith('Columns:'):
            continue

        # Проверяем комментарий
        if stripped.startswith(';;;'):
            current_comment = stripped[3:].strip()
            continue

        # Проверяем строку данных (начинается с цифры)
        data_match = re.match(r'^\s*(\d+)\s+([XRSLD]+)?\s+(\S+)\s+(.*)$', line)
        if data_match:
            flags = data_match.group(2) or ''
            name = data_match.group(3)
            rest = data_match.group(4).strip()

            # Разделяем по множественным пробелам (2+ пробела = разделитель колонок)
            # Числа внутри колонки могут иметь пробелы как тысячные разделители
            columns = re.split(r'\s{2,}', rest)

            # Извлекаем значения
            rx_byte = '0'
            tx_byte = '0'
            rx_packet = '0'
            tx_packet = '0'

            if len(columns) >= 1:
                # Удаляем пробелы внутри числа (тысячные разделители)
                rx_byte = columns[0].replace(' ', '')
            if len(columns) >= 2:
                tx_byte = columns[1].replace(' ', '')
            if len(columns) >= 3:
                rx_packet = columns[2].replace(' ', '')
            if len(columns) >= 4:
                tx_packet = columns[3].replace(' ', '')

            stats[name] = {
                'rx-byte': rx_byte,
                'tx-byte': tx_byte,
                'rx-packet': rx_packet,
                'tx-packet': tx_packet,
                'flags': flags,
            }

            # Добавляем комментарий если есть
            if current_comment:
                stats[name]['comment'] = current_comment
                current_comment = ''

    return stats


def parse_interface_stats(interface_results: List) -> Tuple[List[NetworkInterface], NetworkOverview]:
    """
    Parse interface statistics from command results.

    Поддерживает оба формата RouterOS v7:
    1. /interface print detail - многострочный key=value с комментариями ;;;
    2. /interface print stats - колоночный формат с числами

    Сливаем данные из обоих источников по имени интерфейса.
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
        if '/interface print detail' in r.command:
            detail_output += r.stdout + '\n'
        elif '/interface print stats' in r.command:
            stats_output += r.stdout + '\n'
        elif '/interface print' in r.command:
            # Если просто /interface print - считаем это stats
            if 'Columns:' in r.stdout and 'RX-BYTE' in r.stdout:
                stats_output += r.stdout + '\n'
            else:
                detail_output += r.stdout + '\n'

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
            # Обновляем статистику из stats (приоритет у stats для числовых данных)
            for key, value in stats_data[name].items():
                data[key] = value

        if not data and not name:
            continue

        interface = NetworkInterface()
        interface.name = data.get('name', name)
        interface.type = data.get('type', '')
        interface.mtu = _safe_int(data.get('mtu', '0'))
        interface.running = 'R' in data.get('flags', '') or _safe_bool(data.get('running', 'false'))
        interface.disabled = _safe_bool(data.get('disabled', 'false'))

        # Парсим числа с возможными тысячными разделителями (пробелы)
        rx_byte_str = data.get('rx-byte', '0')
        tx_byte_str = data.get('tx-byte', '0')
        rx_packet_str = data.get('rx-packet', '0')
        tx_packet_str = data.get('tx-packet', '0')

        interface.rx_byte = _safe_int(rx_byte_str.replace(' ', ''))
        interface.tx_byte = _safe_int(tx_byte_str.replace(' ', ''))
        interface.rx_packet = _safe_int(rx_packet_str.replace(' ', ''))
        interface.tx_packet = _safe_int(tx_packet_str.replace(' ', ''))
        # parse_key_value_line заменяет '-' на '_', поэтому используем mac_address
        interface.mac_address = data.get('mac_address', data.get('mac-address', ''))

        interfaces.append(interface)
        logger.debug(f"Parsed interface: {interface.name}, running: {interface.running}")

    overview.total_interfaces = len(interfaces)
    overview.active_interfaces = sum(1 for i in interfaces if i.running)

    return interfaces, overview
