"""Parser for system resource information."""

import logging
import re
from typing import List, Tuple, Optional
from functools import lru_cache

from src.models import SystemResource, SystemHealth, Disk

logger = logging.getLogger(__name__)


@lru_cache(maxsize=32)
def _parse_value_with_unit(value_str: str) -> Tuple[float, str]:
    """Parse value with unit (e.g., '1024KiB' -> (1024, 'KiB') or '66.8MiB' -> (66.8, 'MiB'))."""
    # Support both integer and float values
    match = re.match(r'(\d+(?:\.\d+)?)(\w*)', value_str)
    if match:
        return float(match.group(1)), match.group(2)
    return 0.0, ''


def _parse_size_to_bytes(value: float, unit: str) -> int:
    """Convert size with unit to bytes."""
    multipliers = {
        '': 1,
        'B': 1,
        'KiB': 1024,
        'MiB': 1024 ** 2,
        'GiB': 1024 ** 3,
        'TiB': 1024 ** 4,
    }
    return int(value * multipliers.get(unit, 1))


def parse_system_resource(results: List) -> SystemResource:
    """
    Parse system resource information from /system resource print.

    Формат вывода RouterOS:
     uptime: 5d12h30m
     version: 7.22 (stable)
     build-time: Dec/12/2025 10:30:00
     board-name: hAP ax^3
     architecture: arm64
     cpu-count: 4
     cpu-frequency: 1800MHz
     cpu-load: 5%,12%,8%,15%
     free-memory: 524288KiB
     total-memory: 1073741824
     free-hdd: 107374182
     total-hdd: 536870912
     write-sectors-since-reboot: 123456
     bad-blocks: 0
     bad-blocks-percent: 0%
     factory-firmware: 7.12
     current-firmware: 7.22
     upgrade-firmware:
     platform: hAP ax^3
     serial-number: ABCD1234
    """
    resource = SystemResource()

    if not results or results[0].has_error:
        logger.warning("No system resource data available")
        return resource

    output = results[0].stdout

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Парсинг key: value или key=value
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip().lower().replace('-', '_')
                value = parts[1].strip()
            else:
                continue
        elif '=' in line:
            parts = line.split('=', 1)
            if len(parts) == 2:
                key = parts[0].strip().lower().replace('-', '_')
                value = parts[1].strip()
            else:
                continue
        else:
            continue

        # Обработка конкретных полей
        if key == 'uptime':
            resource.uptime = value
        elif key == 'version':
            resource.version = value
        elif key == 'build_time' or key == 'build-time':
            resource.build_time = value
        elif key == 'board_name' or key == 'board-name':
            resource.board_name = value
        elif key == 'architecture':
            resource.architecture = value
        elif key == 'cpu_count' or key == 'cpu-count':
            try:
                resource.cpu_count = int(value)
            except ValueError:
                logger.debug(f"Invalid cpu_count value: {value}")
        elif key == 'cpu_load' or key == 'cpu-load':
            # CPU load может быть в формате "5%,12%,8%,15%"
            resource.cpu_load = [int(x.strip().replace('%', '')) for x in value.split(',') if x.strip()]
        elif key == 'free_memory' or key == 'free-memory':
            val, unit = _parse_value_with_unit(value)
            resource.free_memory = _parse_size_to_bytes(val, unit)
        elif key == 'total_memory' or key == 'total-memory':
            val, unit = _parse_value_with_unit(value)
            resource.total_memory = _parse_size_to_bytes(val, unit)
        elif key == 'free_hdd' or key == 'free-hdd' or key == 'free_hdd_space' or key == 'free-hdd-space':
            val, unit = _parse_value_with_unit(value)
            resource.free_hdd = _parse_size_to_bytes(val, unit)
            logger.debug(f"Parsed free-hdd: {val} {unit} = {resource.free_hdd} bytes")
        elif key == 'total_hdd' or key == 'total-hdd' or key == 'total_hdd_space' or key == 'total-hdd-space':
            val, unit = _parse_value_with_unit(value)
            resource.total_hdd = _parse_size_to_bytes(val, unit)
            logger.debug(f"Parsed total-hdd: {val} {unit} = {resource.total_hdd} bytes")
        elif key == 'write_sectors_since_reboot' or key == 'write-sectors-since-reboot':
            try:
                resource.write_sectors_since_reboot = int(value)
            except ValueError:
                logger.debug(f"Invalid write_sectors_since_reboot value: {value}")
        elif key == 'bad_blocks' or key == 'bad-blocks':
            try:
                resource.bad_blocks = int(value)
            except ValueError:
                logger.debug(f"Invalid bad_blocks value: {value}")
        elif key == 'bad_blocks_percent' or key == 'bad-blocks-percent':
            try:
                resource.bad_blocks_percent = float(value.replace('%', ''))
            except ValueError:
                logger.debug(f"Invalid bad_blocks_percent value: {value}")
        elif key == 'factory_firmware' or key == 'factory-firmware':
            resource.factory_firmware = value
        elif key == 'current_firmware' or key == 'current-firmware':
            resource.current_firmware = value
        elif key == 'upgrade_firmware' or key == 'upgrade-firmware':
            resource.upgrade_firmware = value
        elif key == 'platform':
            resource.platform = value
        elif key == 'serial_number' or key == 'serial-number':
            resource.serial_number = value
        elif key == 'architecture_name' or key == 'architecture-name':
            resource.architecture_name = value
        elif key == 'free_heap' or key == 'free-heap':
            val, unit = _parse_value_with_unit(value)
            resource.free_heap = _parse_size_to_bytes(val, unit)
        elif key == 'heap_size' or key == 'heap-size':
            val, unit = _parse_value_with_unit(value)
            resource.heap_size = _parse_size_to_bytes(val, unit)

    return resource


def parse_system_health(results: List) -> SystemHealth:
    """
    Parse system health information from /system health print.

    Формат вывода RouterOS:
     temperature: 45C
     voltage: 12V
     current: 0.5A
     psu1-state: ok
     psu2-state: unknown
     fan1-speed: 2500RPM
     poe-out-state: powered-on
     poe-out-current: 150mA
    """
    health = SystemHealth()

    if not results or results[0].has_error:
        logger.warning("No system health data available")
        return health

    output = results[0].stdout

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue

        # Парсинг key: value или key=value
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip().lower().replace('-', '_')
                value = parts[1].strip()
            else:
                continue
        elif '=' in line:
            parts = line.split('=', 1)
            if len(parts) == 2:
                key = parts[0].strip().lower().replace('-', '_')
                value = parts[1].strip()
            else:
                continue
        else:
            continue

        # Обработка конкретных полей
        if key == 'temperature':
            health.temperature = value
        elif key == 'voltage':
            health.voltage = value
        elif key == 'current':
            health.current = value
        elif key == 'psu1_state' or key == 'psu1-state':
            health.psu1_state = value
        elif key == 'psu2_state' or key == 'psu2-state':
            health.psu2_state = value
        elif key == 'psu1_voltage' or key == 'psu1-voltage':
            health.psu1_voltage = value
        elif key == 'psu2_voltage' or key == 'psu2-voltage':
            health.psu2_voltage = value
        elif key == 'fan1_speed' or key == 'fan1-speed':
            health.fan1_speed = value
        elif key == 'fan2_speed' or key == 'fan2-speed':
            health.fan2_speed = value
        elif key == 'poe_out_state' or key == 'poe-out-state':
            health.poe_out_state = value
        elif key == 'poe_out_current' or key == 'poe-out-current':
            health.poe_out_current = value
        elif key == 'board_temperature1' or key == 'board-temperature1':
            health.board_temperature1 = value
        elif key == 'board_temperature2' or key == 'board-temperature2':
            health.board_temperature2 = value
        elif key == 'junction_temperature' or key == 'junction-temperature':
            health.junction_temperature = value

    return health


def parse_system_package(results: List) -> List:
    """
    Parse system package information from /system package print.

    Возвращает список словарей с информацией о пакетах.
    """

    packages: list[dict] = []

    if not results or results[0].has_error:
        logger.warning("No system package data available")
        return packages

    output = results[0].stdout

    # Парсинг многострочного формата
    current_package: Optional[dict] = None
    lines = output.split('\n')

    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue

        # Проверяем начало новой записи (цифра в начале)
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущий пакет
            if current_package:
                packages.append(current_package)

            # Начинаем новый пакет
            current_package = {}
            rest = entry_match.group(3) or ''

            # Парсим rest если там есть данные
            if '=' in rest:
                for part in rest.split():
                    if '=' in part:
                        k, v = part.split('=', 1)
                        current_package[k] = v
            continue

        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_package is not None:
                for part in line.strip().split():
                    if '=' in part:
                        k, v = part.split('=', 1)
                        current_package[k] = v
            continue

    # Сохраняем последний пакет
    if current_package:
        packages.append(current_package)

    return packages


def parse_system_package_update(results: List) -> dict:
    """
    Parse system package update information from /system package update print.

    Возвращает словарь с информацией об обновлениях.
    """
    update_info = {
        'installed_version': '',
        'latest_version': '',
        'update_available': False,
        'channel': '',
        'scheduled': False,
    }

    if not results or results[0].has_error:
        logger.warning("No system package update data available")
        return update_info

    output = results[0].stdout

    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue

        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip().lower().replace('-', '_')
                value = parts[1].strip()

                if key == 'installed_version' or key == 'installed-version':
                    update_info['installed_version'] = value
                elif key == 'latest_version' or key == 'latest-version':
                    update_info['latest_version'] = value
                    update_info['update_available'] = value != update_info['installed_version']
                elif key == 'channel':
                    update_info['channel'] = value
                elif key == 'scheduled':
                    update_info['scheduled'] = value.lower() == 'true' or value.lower() == 'yes'
        elif '=' in line:
            parts = line.split('=', 1)
            if len(parts) == 2:
                key = parts[0].strip().lower().replace('-', '_')
                value = parts[1].strip()

                if key == 'installed_version' or key == 'installed-version':
                    update_info['installed_version'] = value
                elif key == 'latest_version' or key == 'latest-version':
                    update_info['latest_version'] = value
                    update_info['update_available'] = value != update_info['installed_version']
                elif key == 'channel':
                    update_info['channel'] = value
                elif key == 'scheduled':
                    update_info['scheduled'] = value.lower() == 'true' or value.lower() == 'yes'

    return update_info


def parse_disks(results: List) -> List[Disk]:
    """
    Parse disk information from /disk print.

    RouterOS v7 format:
     Flags: R - REMOVABLE
     0 R name="usb1" type="usb" path="/usb1" total-size=29.8GiB free-size=22.1GiB
    """
    disks: List[Disk] = []
    disk_names_seen: set = set()

    if not results:
        logger.debug("No disk data available")
        return disks

    for result in results:
        if result.has_error:
            continue

        # Skip export output - it doesn't contain physical disk info
        if '/export' in result.command:
            continue

        output = result.stdout

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            # Must have name= and total-size= to be a valid disk entry
            if 'name=' not in line or 'total-size=' not in line:
                continue

            disk_data = {}

            # Extract name
            name_match = re.search(r'name=["\']?([^"\'\s]+)["\']?', line)
            if name_match:
                disk_name = name_match.group(1)
                # Skip if already processed this disk
                if disk_name in disk_names_seen:
                    continue
                disk_names_seen.add(disk_name)
                disk_data['name'] = disk_name

            # Extract type
            type_match = re.search(r'type=["\']?([^"\'\s]+)["\']?', line)
            if type_match:
                disk_data['type'] = type_match.group(1)

            # Extract path
            path_match = re.search(r'path=["\']?([^"\'\s]+)["\']?', line)
            if path_match:
                disk_data['path'] = path_match.group(1)

            # Extract total-size with unit
            total_match = re.search(r'total-size=(\d+(?:\.\d+)?)(\w*)', line)
            if total_match:
                disk_data['total_size'] = _parse_size_to_bytes(float(total_match.group(1)), total_match.group(2))

            # Extract free-size with unit
            free_match = re.search(r'free-size=(\d+(?:\.\d+)?)(\w*)', line)
            if free_match:
                disk_data['free_size'] = _parse_size_to_bytes(float(free_match.group(1)), free_match.group(2))

            # Create Disk object if we have at least name and total size
            total_size_val = disk_data.get('total_size', 0)
            if disk_data.get('name') and isinstance(total_size_val, int) and total_size_val > 0:
                disk = Disk(
                    name=disk_data.get('name', ''),
                    type=disk_data.get('type', ''),
                    path=disk_data.get('path', ''),
                    total_size=total_size_val,
                    free_size=disk_data.get('free_size', 0)
                )

                # Calculate used percent
                if disk.total_size > 0:
                    disk.used_percent = ((disk.total_size - disk.free_size) / disk.total_size) * 100

                disks.append(disk)

    return disks
