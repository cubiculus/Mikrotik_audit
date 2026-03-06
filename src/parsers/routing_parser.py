"""Parser for routing and DNS information."""

import logging
import re
from typing import List, Dict, Set
from functools import lru_cache

from src.models import Route, DNSInfo

logger = logging.getLogger(__name__)

# Предкомпилированные паттерны
COMMAND_ROUTE_PATTERN = '/ip route print'
COMMAND_ROUTING_RULE_PATTERN = '/routing rule print'
COMMAND_DNS_PATTERN = '/ip dns print'
COMMAND_DNS_STATIC_PATTERN = '/ip dns static print'

SERVERS_PATTERN = re.compile(r'servers:\s*(.*)')
USE_DOH_PATTERN = re.compile(r'use-doh:\s*(\S+)')
DOH_SERVER_PATTERN = re.compile(r'doh-server:\s*(.*)')
ALLOW_REMOTE_PATTERN = re.compile(r'allow-remote-requests:\s*(\S+)')
CACHE_SIZE_PATTERN = re.compile(r'cache-size:\s*(\d+)')

# Известные ключи для маршрутов
ROUTE_KNOWN_FIELDS = {
    'dst-address', 'gateway', 'routing-mark', 'disabled', 'distance', 'comment'
}


@lru_cache(maxsize=256)
def _parse_route_line_cached(line: str) -> Dict[str, str]:
    """Кэшированная функция для парсинга строки маршрута."""
    route_dict = {}
    for part in line.split():
        if '=' in part:
            try:
                k, v = part.split('=', 1)
                route_dict[k] = v
            except ValueError:
                continue
    return route_dict


def _safe_bool(value: str) -> bool:
    """Безопасное преобразование в булево значение."""
    return value.lower() in ('yes', 'true')


def _safe_int(value: str, default: int = 0) -> int:
    """Безопасное преобразование в целое число."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _build_other_fields(rule_dict: Dict[str, str], known_fields: Set[str]) -> Dict[str, str]:
    """Строит словарь other_fields, исключая известные поля."""
    return {k: v for k, v in rule_dict.items() if k not in known_fields}


def parse_routes(results: List) -> List[Route]:
    """Parse routing table entries."""
    routes = []
    for r in results:
        if r.command.startswith(COMMAND_ROUTE_PATTERN):
            for line in r.stdout.split('\n'):
                if 'dst-address=' in line:
                    route_dict = _parse_route_line_cached(line)
                    route = Route()
                    route.dst_address = route_dict.get('dst-address', '')
                    route.gateway = route_dict.get('gateway', '')
                    route.routing_mark = route_dict.get('routing-mark', '')
                    route.disabled = _safe_bool(route_dict.get('disabled', 'false'))
                    route.distance = route_dict.get('distance', '')
                    route.comment = route_dict.get('comment', '')
                    route.other = _build_other_fields(route_dict, ROUTE_KNOWN_FIELDS)
                    routes.append(route)
    return routes


def parse_routing_rules(results: List) -> List[dict]:
    """Parse routing rules."""
    routing_rules = []
    for r in results:
        if r.command.startswith(COMMAND_ROUTING_RULE_PATTERN):
            for line in r.stdout.split('\n'):
                if 'action=' in line or 'src-address=' in line or 'dst-address=' in line:
                    rule_dict = {}
                    for part in line.split():
                        if '=' in part:
                            try:
                                k, v = part.split('=', 1)
                                rule_dict[k] = v
                            except ValueError:
                                continue
                    routing_rules.append(rule_dict)
    return routing_rules


def parse_dns_config(results: List) -> DNSInfo:
    """Parse DNS configuration."""
    dns_info = DNSInfo()
    
    for r in results:
        if r.command.startswith(COMMAND_DNS_PATTERN):
            for line in r.stdout.split('\n'):
                # Parse DNS servers
                servers_match = SERVERS_PATTERN.search(line)
                if servers_match:
                    servers = servers_match.group(1).strip()
                    dns_info.servers = [s.strip() for s in servers.split(',') if s.strip()]
                
                # Parse use-doh
                use_doh_match = USE_DOH_PATTERN.search(line)
                if use_doh_match:
                    dns_info.use_doh = _safe_bool(use_doh_match.group(1))
                
                # Parse doh-server
                doh_server_match = DOH_SERVER_PATTERN.search(line)
                if doh_server_match:
                    dns_info.doh_server = doh_server_match.group(1).strip()
                
                # Parse allow-remote-requests
                allow_remote_match = ALLOW_REMOTE_PATTERN.search(line)
                if allow_remote_match:
                    dns_info.allow_remote = _safe_bool(allow_remote_match.group(1))
                
                # Parse cache-size
                cache_size_match = CACHE_SIZE_PATTERN.search(line)
                if cache_size_match:
                    dns_info.cache_size = _safe_int(cache_size_match.group(1))
        
        if r.command.startswith(COMMAND_DNS_STATIC_PATTERN):
            # Parse static DNS entries
            for line in r.stdout.split('\n'):
                if 'name=' in line and 'address=' in line:
                    entry = {}
                    for part in line.split():
                        if '=' in part:
                            try:
                                k, v = part.split('=', 1)
                                entry[k] = v
                            except ValueError:
                                continue
                    dns_info.static_entries.append(entry)
    
    return dns_info