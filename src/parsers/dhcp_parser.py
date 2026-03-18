"""Parser for DHCP lease information."""

import logging
import re
import shlex
from typing import List, Tuple
from functools import lru_cache

from src.models import DHCPLease, NetworkOverview

logger = logging.getLogger(__name__)

# Предкомпилированные регулярные выражения для оптимизации
ENTRY_NUMBER_PATTERN = re.compile(r'^\s*(\d+|#)\s+(.*)')
COMMENT_PATTERN = re.compile(r'^\s*;;+\s*(.*)$')
FLAGS_PATTERN = re.compile(r'^([XDRSAI]+)\s+(.*)')
CONTINUATION_PATTERN = re.compile(r'^\s{4,}|\t')
NEW_ENTRY_PATTERN = re.compile(r'^\s*(\d|#)|;;+')


def parse_dhcp_leases(results: List) -> Tuple[List[DHCPLease], NetworkOverview]:
    """Parse DHCP leases - специальный парсер для формата MikroTik."""
    leases: List[DHCPLease] = []
    overview = NetworkOverview()

    if not results or results[0].has_error:
        logger.warning("No DHCP lease data available")
        return leases, overview

    try:
        lines = results[0].stdout.split('\n')
        i = 0
        total_lines = len(lines)

        while i < total_lines:
            line = lines[i].rstrip()

            # Пропускаем заголовок и пустые строки
            if not line or line.startswith('Flags:'):
                i += 1
                continue

            # Если строка начинается с комментария ;;;
            comment = ''
            if line.strip().startswith(';;;'):
                comment = line.strip()[3:].strip()
                i += 1
                if i >= total_lines:
                    break
                line = lines[i].rstrip()

            # Проверяем начало новой записи (цифра или # в начале)
            if not NEW_ENTRY_PATTERN.match(line):
                i += 1
                continue

            # Парсим номер записи (может быть # или число)
            match = ENTRY_NUMBER_PATTERN.match(line)
            if not match:
                i += 1
                continue

            entry_num = match.group(1)
            rest_part = match.group(2).strip()

            # Проверяем наличие комментария на той же строке
            comment = ''

            # Проверяем формат: "#    ;;; Nintendo" - комментарий сразу после номера
            if rest_part.startswith(';;;'):
                parts = rest_part.split(' ', 1)
                if len(parts) > 1 and parts[0] == ';;;':
                    comment = parts[1]
                    i += 1
                    if i >= total_lines:
                        break
                    line = lines[i].rstrip()
                    rest_part = line.strip()
                elif len(parts) == 1:
                    comment = rest_part[3:]
                    i += 1
                    if i >= total_lines:
                        break
                    line = lines[i].rstrip()
                    rest_part = line.strip()
                else:
                    comment = parts[0][3:]
                    rest_part = parts[1] if len(parts) > 1 else ''

            # Проверяем флаги
            flags_match = FLAGS_PATTERN.match(rest_part)
            if flags_match:
                flags = flags_match.group(1)
                rest_of_line = flags_match.group(2).strip()
            else:
                flags = ''
                rest_of_line = rest_part

            # Тип записи определяется ТОЛЬКО по флагу D
            is_dynamic = 'D' in flags

            # Собираем все строки записи (продолжения с отступами)
            full_entry = rest_of_line
            i += 1
            while i < total_lines:
                next_line = lines[i].rstrip()
                # Проверяем продолжение по отступам
                if CONTINUATION_PATTERN.match(next_line):
                    full_entry += ' ' + next_line.strip()
                    i += 1
                # Новая запись
                elif NEW_ENTRY_PATTERN.match(next_line):
                    break
                else:
                    i += 1

            # Парсим данные из строки
            lease_data = _parse_lease_data(full_entry)

            # Create lease object
            lease = DHCPLease()
            lease.address = lease_data.get('address', '')
            lease.mac_address = lease_data.get('mac_address', '')
            lease.host_name = lease_data.get('host_name', '')
            lease.client_hostname = lease_data.get('host_name', '')
            lease.address_lists = lease_data.get('address_lists', '')
            lease.expires_after = lease_data.get('expires_after', '')
            lease.last_seen = lease_data.get('last_seen', '')
            lease.server = lease_data.get('server', '')
            lease.comment = comment
            lease.dynamic = is_dynamic  # Single boolean field
            lease.lease_status = "Dynamic" if is_dynamic else "Static"

            # Добавляем запись если есть данные
            if lease.address or lease.mac_address:
                leases.append(lease)
                logger.debug(f"Parsed DHCP lease #{entry_num}: {lease.address} -> {lease.lease_status} (flags: '{flags.strip()}')")

        overview.dhcp_leases_count = len(leases)
        overview.dhcp_active_leases = len([lease for lease in leases if lease.lease_status == "Dynamic" and lease.expires_after != "never"])

    except Exception as e:
        logger.error(f"Error parsing DHCP leases: {e}", exc_info=True)
        return [], overview

    return leases, overview


@lru_cache(maxsize=256)
def _parse_lease_data_cached(entry_str: str) -> dict:
    """Кэшированная версия парсинга данных аренды с поддержкой кавычек."""
    lease_data = {}

    # Используем shlex.split для корректной обработки значений в кавычках
    try:
        parts = shlex.split(entry_str)
    except ValueError:
        # Если shlex не справился (например, незакрытые кавычки), используем обычный split
        parts = entry_str.split()

    for part in parts:
        if '=' in part:
            try:
                key, value = part.split('=', 1)
                value = value.strip('"\'')
                normalized_key = key.replace('-', '_')
                lease_data[normalized_key] = value
            except ValueError:
                continue
    return lease_data


def _parse_lease_data(entry_str: str) -> dict:
    """Парсинг данных аренды из строки."""
    return _parse_lease_data_cached(entry_str)
