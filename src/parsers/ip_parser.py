"""Parser for IP address information."""

import logging
from typing import List, Tuple
from functools import lru_cache

from src.models import IPAddress, NetworkOverview

logger = logging.getLogger(__name__)

# Известные ключи для IP адресов
IP_ADDRESS_KNOWN_KEYS = {
    'address', 'network', 'interface', 'actual-interface', 'comment'
}


@lru_cache(maxsize=256)
def _parse_ip_data_cached(line: str) -> dict:
    """Кэшированная функция для парсинга строки IP адреса в словарь."""
    address_data = {}
    for part in line.split():
        if '=' in part:
            try:
                key, value = part.split('=', 1)
                address_data[key] = value
            except ValueError:
                continue
    return address_data


def parse_ip_address_results(ip_results: List) -> Tuple[List[IPAddress], NetworkOverview]:
    """Parse IP address results."""
    ip_addresses: List[IPAddress] = []
    overview = NetworkOverview()

    if not ip_results or ip_results[0].has_error:
        logger.warning("No IP address data available")
        return ip_addresses, overview
    
    for line in ip_results[0].stdout.split('\n'):
        if 'address=' in line:
            address_data = _parse_ip_data_cached(line)
            
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