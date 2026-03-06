"""Parser for firewall rules (NAT, Filter, Mangle)."""

import logging
from typing import List, Dict, Set
from functools import lru_cache

from src.models import NATRule, FilterRule, MangleRule

logger = logging.getLogger(__name__)

# Предкомпилированные паттерны
COMMAND_PATTERN_NAT = '/ip firewall nat print'
COMMAND_PATTERN_FILTER = '/ip firewall filter print'
COMMAND_PATTERN_MANGLE = '/ip firewall mangle print'

# Множества известных полей для каждого типа правил
NAT_KNOWN_FIELDS = {
    'chain', 'action', 'disabled', 'comment', 'src-address', 'dst-address',
    'src-address-list', 'dst-address-list', 'protocol', 'src-port', 'dst-port',
    'to-addresses', 'to-ports', 'out-interface', 'in-interface', 'in-interface-list',
    'routing-mark', 'log'
}

FILTER_KNOWN_FIELDS = {
    'chain', 'action', 'disabled', 'comment', 'src-address', 'dst-address',
    'src-address-list', 'dst-address-list', 'protocol', 'src-port', 'dst-port',
    'in-interface', 'out-interface', 'in-interface-list', 'out-interface-list',
    'connection-state', 'connection-nat-state', 'connection-type', 'log', 'log-prefix',
    'packet-mark', 'connection-mark', 'routing-mark'
}

MANGLE_KNOWN_FIELDS = {
    'action', 'chain', 'disabled', 'comment', 'src-address', 'dst-address',
    'src-address-list', 'dst-address-list', 'protocol', 'dst-port', 'src-port',
    'new-connection-mark', 'new-routing-mark', 'routing-mark', 'passthrough'
}


@lru_cache(maxsize=512)
def _parse_rule_line_cached(line: str) -> Dict[str, str]:
    """Кэшированная функция для парсинга строки правила в словарь."""
    rule_dict = {}
    for part in line.split():
        if '=' in part:
            try:
                k, v = part.split('=', 1)
                rule_dict[k] = v
            except ValueError:
                continue
    return rule_dict


def _parse_rule_line(line: str) -> Dict[str, str]:
    """Парсинг строки правила в словарь."""
    return _parse_rule_line_cached(line)


def _build_other_fields(rule_dict: Dict[str, str], known_fields: Set[str]) -> Dict[str, str]:
    """Строит словарь other_fields, исключая известные поля."""
    return {k: v for k, v in rule_dict.items() if k not in known_fields}


def parse_nat_rules(results: List) -> List[NATRule]:
    """Parse NAT firewall rules."""
    nat_rules = []
    for r in results:
        if r.command.startswith(COMMAND_PATTERN_NAT):
            for line in r.stdout.split('\n'):
                if 'action=' in line:
                    rule_dict = _parse_rule_line(line)
                    rule = NATRule()
                    rule.chain = rule_dict.get('chain', '')
                    rule.action = rule_dict.get('action', '')
                    rule.disabled = rule_dict.get('disabled', 'false').lower() in ('yes', 'true')
                    rule.comment = rule_dict.get('comment', '')
                    rule.src_address = rule_dict.get('src-address', '')
                    rule.dst_address = rule_dict.get('dst-address', '')
                    rule.src_address_list = rule_dict.get('src-address-list', '')
                    rule.dst_address_list = rule_dict.get('dst-address-list', '')
                    rule.protocol = rule_dict.get('protocol', '')
                    rule.src_port = rule_dict.get('src-port', '')
                    rule.dst_port = rule_dict.get('dst-port', '')
                    rule.to_addresses = rule_dict.get('to-addresses', '')
                    rule.to_ports = rule_dict.get('to-ports', '')
                    rule.out_interface = rule_dict.get('out-interface', '')
                    rule.in_interface = rule_dict.get('in-interface', '')
                    rule.in_interface_list = rule_dict.get('in-interface-list', '')
                    rule.routing_mark = rule_dict.get('routing-mark', '')
                    rule.log = rule_dict.get('log', '')
                    rule.other = _build_other_fields(rule_dict, NAT_KNOWN_FIELDS)
                    nat_rules.append(rule)
    return nat_rules


def parse_filter_rules(results: List) -> List[FilterRule]:
    """Parse Filter firewall rules."""
    filter_rules = []
    for r in results:
        if r.command.startswith(COMMAND_PATTERN_FILTER):
            for line in r.stdout.split('\n'):
                if 'action=' in line:
                    rule_dict = _parse_rule_line(line)
                    rule = FilterRule()
                    rule.chain = rule_dict.get('chain', '')
                    rule.action = rule_dict.get('action', '')
                    rule.disabled = rule_dict.get('disabled', 'false').lower() in ('yes', 'true')
                    rule.comment = rule_dict.get('comment', '')
                    rule.src_address = rule_dict.get('src-address', '')
                    rule.dst_address = rule_dict.get('dst-address', '')
                    rule.src_address_list = rule_dict.get('src-address-list', '')
                    rule.dst_address_list = rule_dict.get('dst-address-list', '')
                    rule.protocol = rule_dict.get('protocol', '')
                    rule.src_port = rule_dict.get('src-port', '')
                    rule.dst_port = rule_dict.get('dst-port', '')
                    rule.in_interface = rule_dict.get('in-interface', '')
                    rule.out_interface = rule_dict.get('out-interface', '')
                    rule.in_interface_list = rule_dict.get('in-interface-list', '')
                    rule.out_interface_list = rule_dict.get('out-interface-list', '')
                    rule.connection_state = rule_dict.get('connection-state', '')
                    rule.connection_nat_state = rule_dict.get('connection-nat-state', '')
                    rule.connection_type = rule_dict.get('connection-type', '')
                    rule.log = rule_dict.get('log', '')
                    rule.log_prefix = rule_dict.get('log-prefix', '')
                    rule.packet_mark = rule_dict.get('packet-mark', '')
                    rule.connection_mark = rule_dict.get('connection-mark', '')
                    rule.routing_mark = rule_dict.get('routing-mark', '')
                    rule.other = _build_other_fields(rule_dict, FILTER_KNOWN_FIELDS)
                    filter_rules.append(rule)
    return filter_rules


def parse_mangle_rules(results: List) -> List[MangleRule]:
    """Parse Mangle firewall rules."""
    mangle_rules = []
    for r in results:
        if r.command.startswith(COMMAND_PATTERN_MANGLE):
            for line in r.stdout.split('\n'):
                if 'action=' in line:
                    rule_dict = _parse_rule_line(line)
                    rule = MangleRule()
                    rule.action = rule_dict.get('action', '')
                    rule.chain = rule_dict.get('chain', '')
                    rule.disabled = rule_dict.get('disabled', 'false').lower() in ('yes', 'true')
                    rule.comment = rule_dict.get('comment', '')
                    rule.src_address = rule_dict.get('src-address', '')
                    rule.dst_address = rule_dict.get('dst-address', '')
                    rule.protocol = rule_dict.get('protocol', '')
                    rule.dst_port = rule_dict.get('dst-port', '')
                    rule.src_port = rule_dict.get('src-port', '')
                    rule.new_connection_mark = rule_dict.get('new-connection-mark', '')
                    rule.new_routing_mark = rule_dict.get('new-routing-mark', '')
                    rule.routing_mark = rule_dict.get('routing-mark', '')
                    rule.passthrough = rule_dict.get('passthrough', '')
                    rule.src_address_list = rule_dict.get('src-address-list', '')
                    rule.dst_address_list = rule_dict.get('dst-address-list', '')
                    rule.other = _build_other_fields(rule_dict, MANGLE_KNOWN_FIELDS)
                    mangle_rules.append(rule)
    return mangle_rules