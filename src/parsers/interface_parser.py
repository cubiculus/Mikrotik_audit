"""Parser for network interface statistics."""

import logging
from typing import List, Tuple
from functools import lru_cache

from src.models import NetworkInterface, NetworkOverview

logger = logging.getLogger(__name__)

# Известные ключи интерфейса
INTERFACE_KNOWN_KEYS = {
    'name', 'type', 'mtu', 'running', 'disabled', 'rx-byte', 'tx-byte',
    'rx-packet', 'tx-packet', 'mac-address'
}


@lru_cache(maxsize=128)
def _parse_interface_data_cached(line: str) -> dict:
    """Кэшированная функция для парсинга строки интерфейса в словарь."""
    interface_data = {}
    for part in line.split():
        if '=' in part:
            try:
                key, value = part.split('=', 1)
                interface_data[key] = value
            except ValueError:
                continue
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


def parse_interface_stats(interface_results: List) -> Tuple[List[NetworkInterface], NetworkOverview]:
    """Parse interface statistics from command results."""
    interfaces: List[NetworkInterface] = []
    overview = NetworkOverview()

    if not interface_results or interface_results[0].has_error:
        logger.warning("No interface data available")
        return interfaces, overview
    
    for line in interface_results[0].stdout.split('\n'):
        if 'name=' in line and 'rx-byte=' in line:
            interface_data = _parse_interface_data_cached(line)
            
            interface = NetworkInterface()
            interface.name = interface_data.get('name', '')
            interface.type = interface_data.get('type', '')
            interface.mtu = _safe_int(interface_data.get('mtu', '0'))
            interface.running = _safe_bool(interface_data.get('running', 'false'))
            interface.disabled = _safe_bool(interface_data.get('disabled', 'false'))
            interface.rx_byte = _safe_int(interface_data.get('rx-byte', '0'))
            interface.tx_byte = _safe_int(interface_data.get('tx-byte', '0'))
            interface.rx_packet = _safe_int(interface_data.get('rx-packet', '0'))
            interface.tx_packet = _safe_int(interface_data.get('tx-packet', '0'))
            interface.mac_address = interface_data.get('mac-address', '')
            
            interfaces.append(interface)
            logger.debug(f"Parsed interface: {interface.name}, running: {interface.running}")
    
    overview.total_interfaces = len(interfaces)
    overview.active_interfaces = sum(1 for i in interfaces if i.running)
    
    return interfaces, overview