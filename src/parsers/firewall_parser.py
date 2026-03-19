"""Parser for firewall rules (NAT, Filter, Mangle)."""

import logging
import re
from typing import List, Dict, Set, Optional

from src.models import NATRule, FilterRule, MangleRule
from src.parsers.utils import parse_key_value_line

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


def _parse_rule_line(line: str) -> Dict[str, str]:
    """Парсинг строки правила в словарь."""
    # Remove leading whitespace from RouterOS v7 format
    line = line.lstrip()
    return parse_key_value_line(line)


def _build_other_fields(rule_dict: Dict[str, str], known_fields: Set[str]) -> Dict[str, str]:
    """Строит словарь other_fields, исключая известные поля."""
    return {k: v for k, v in rule_dict.items() if k not in known_fields}


def _parse_rules_with_comments(lines: List[str], known_fields: Set[str]) -> List[Dict[str, str]]:
    """
    Универсальная функция парсинга правил firewall с поддержкой комментариев.

    Формат RouterOS 7:
     1    ;;; 1. FastTrack (MUST BE FIRST!)
          chain=forward action=fasttrack-connection
          log=no log-prefix=""

    Args:
        lines: Список строк вывода команды
        known_fields: Множество известных полей для фильтрации other-полей

    Returns:
        Список словарей с данными правил
    """
    rules = []
    pending_comment: Optional[str] = None
    current_rule_data: Optional[Dict[str, str]] = None
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        i += 1

        # Пропускаем пустые строки и заголовки
        if not stripped or stripped.startswith('Flags:'):
            continue

        # Проверяем комментарий (;;; в начале строки)
        if stripped.startswith(';;;'):
            pending_comment = stripped[3:].strip()
            continue

        # Проверяем начало правила (номер в начале строки)
        # Формат: " 1    ;;; comment" или " 1  R  chain=forward" или " 1    ;;; comment"
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущее правило если есть
            if current_rule_data:
                rules.append(current_rule_data)
                current_rule_data = None

            rest = entry_match.group(3) or ''

            # Если после номера сразу комментарий (;;; может быть после пробелов)
            rest_stripped = rest.lstrip()
            if rest_stripped.startswith(';;;'):
                pending_comment = rest_stripped[3:].strip()
                # Правило будет на следующих строках
                current_rule_data = {}
                continue

            # Если после номера идут данные правила
            if rest and '=' in rest:
                current_rule_data = _parse_rule_line(rest)
                if pending_comment and 'comment' not in current_rule_data:
                    current_rule_data['comment'] = pending_comment
                    pending_comment = None
                continue

            # Если после номера только флаги без данных - правило на следующих строках
            if rest.strip():
                current_rule_data = {}
                continue

        # Продолжение правила (строка с отступом и key=value)
        if (line.startswith('      ') or line.startswith('\t')) and '=' in stripped:
            if current_rule_data is not None:
                # Собираем данные с продолжения
                data = _parse_rule_line(stripped)
                current_rule_data.update(data)
                # Добавляем комментарий если есть и ещё не добавлен
                if pending_comment and 'comment' not in current_rule_data:
                    current_rule_data['comment'] = pending_comment
                    pending_comment = None
            continue

        # Строка с отступом 2+ пробела и key=value (альтернативный формат)
        if line.startswith('  ') and '=' in stripped and not stripped.startswith(';;;'):
            if current_rule_data is not None:
                data = _parse_rule_line(stripped)
                current_rule_data.update(data)
                # Добавляем комментарий если есть и ещё не добавлен
                if pending_comment and 'comment' not in current_rule_data:
                    current_rule_data['comment'] = pending_comment
                    pending_comment = None
            continue

    # Сохраняем последнее правило
    if current_rule_data:
        rules.append(current_rule_data)

    return rules


def parse_nat_rules(results: List) -> List[NATRule]:
    """Parse NAT firewall rules."""
    nat_rules_dicts = []
    for r in results:
        if r.command.startswith(COMMAND_PATTERN_NAT):
            lines = r.stdout.split('\n')
            rules = _parse_rules_with_comments(lines, NAT_KNOWN_FIELDS)
            nat_rules_dicts.extend(rules)

    # Конвертируем словари в объекты NATRule
    # parse_key_value_line заменяет '-' на '_', поэтому используем ключи с '_'
    nat_rules = []
    for rule_dict in nat_rules_dicts:
        rule = NATRule()
        rule.chain = rule_dict.get('chain', '')
        rule.action = rule_dict.get('action', '')
        rule.disabled = rule_dict.get('disabled', 'no') == 'yes'
        rule.comment = rule_dict.get('comment', '')
        rule.src_address = rule_dict.get('src_address', rule_dict.get('src-address', ''))
        rule.dst_address = rule_dict.get('dst_address', rule_dict.get('dst-address', ''))
        rule.src_address_list = rule_dict.get('src_address_list', rule_dict.get('src-address-list', ''))
        rule.dst_address_list = rule_dict.get('dst_address_list', rule_dict.get('dst-address-list', ''))
        rule.protocol = rule_dict.get('protocol', '')
        rule.src_port = rule_dict.get('src_port', rule_dict.get('src-port', ''))
        rule.dst_port = rule_dict.get('dst_port', rule_dict.get('dst-port', ''))
        rule.to_addresses = rule_dict.get('to_addresses', rule_dict.get('to-addresses', ''))
        rule.to_ports = rule_dict.get('to_ports', rule_dict.get('to-ports', ''))
        rule.out_interface = rule_dict.get('out_interface', rule_dict.get('out-interface', ''))
        rule.in_interface = rule_dict.get('in_interface', rule_dict.get('in-interface', ''))
        rule.in_interface_list = rule_dict.get('in_interface_list', rule_dict.get('in-interface-list', ''))
        rule.routing_mark = rule_dict.get('routing_mark', rule_dict.get('routing-mark', ''))
        rule.log = rule_dict.get('log', '')
        rule.other = {k: v for k, v in rule_dict.items() if k not in NAT_KNOWN_FIELDS}
        nat_rules.append(rule)

    return nat_rules


def parse_filter_rules(results: List) -> List[FilterRule]:
    """Parse Filter firewall rules."""
    filter_rules_dicts = []
    for r in results:
        if r.command.startswith(COMMAND_PATTERN_FILTER):
            lines = r.stdout.split('\n')
            rules = _parse_rules_with_comments(lines, FILTER_KNOWN_FIELDS)
            filter_rules_dicts.extend(rules)

    # Конвертируем словари в объекты FilterRule
    # parse_key_value_line заменяет '-' на '_', поэтому используем ключи с '_'
    filter_rules = []
    for rule_dict in filter_rules_dicts:
        rule = FilterRule()
        rule.chain = rule_dict.get('chain', '')
        rule.action = rule_dict.get('action', '')
        rule.disabled = rule_dict.get('disabled', 'no') == 'yes'
        rule.comment = rule_dict.get('comment', '')
        rule.src_address = rule_dict.get('src_address', rule_dict.get('src-address', ''))
        rule.dst_address = rule_dict.get('dst_address', rule_dict.get('dst-address', ''))
        rule.src_address_list = rule_dict.get('src_address_list', rule_dict.get('src-address-list', ''))
        rule.dst_address_list = rule_dict.get('dst_address_list', rule_dict.get('dst-address-list', ''))
        rule.protocol = rule_dict.get('protocol', '')
        rule.src_port = rule_dict.get('src_port', rule_dict.get('src-port', ''))
        rule.dst_port = rule_dict.get('dst_port', rule_dict.get('dst-port', ''))
        rule.in_interface = rule_dict.get('in_interface', rule_dict.get('in-interface', ''))
        rule.out_interface = rule_dict.get('out_interface', rule_dict.get('out-interface', ''))
        rule.in_interface_list = rule_dict.get('in_interface_list', rule_dict.get('in-interface-list', ''))
        rule.out_interface_list = rule_dict.get('out_interface_list', rule_dict.get('out-interface-list', ''))
        rule.connection_state = rule_dict.get('connection_state', rule_dict.get('connection-state', ''))
        rule.connection_nat_state = rule_dict.get('connection_nat_state', rule_dict.get('connection-nat-state', ''))
        rule.connection_type = rule_dict.get('connection_type', rule_dict.get('connection-type', ''))
        rule.log = rule_dict.get('log', '')
        rule.log_prefix = rule_dict.get('log_prefix', rule_dict.get('log-prefix', ''))
        rule.packet_mark = rule_dict.get('packet_mark', rule_dict.get('packet-mark', ''))
        rule.connection_mark = rule_dict.get('connection_mark', rule_dict.get('connection-mark', ''))
        rule.routing_mark = rule_dict.get('routing_mark', rule_dict.get('routing-mark', ''))
        rule.other = {k: v for k, v in rule_dict.items() if k not in FILTER_KNOWN_FIELDS}
        filter_rules.append(rule)

    return filter_rules


def parse_mangle_rules(results: List) -> List[MangleRule]:
    """Parse Mangle firewall rules."""
    mangle_rules_dicts = []
    for r in results:
        if r.command.startswith(COMMAND_PATTERN_MANGLE):
            lines = r.stdout.split('\n')
            rules = _parse_rules_with_comments(lines, MANGLE_KNOWN_FIELDS)
            mangle_rules_dicts.extend(rules)

    # Конвертируем словари в объекты MangleRule
    # parse_key_value_line заменяет '-' на '_', поэтому используем ключи с '_'
    mangle_rules = []
    for rule_dict in mangle_rules_dicts:
        rule = MangleRule()
        rule.action = rule_dict.get('action', '')
        rule.chain = rule_dict.get('chain', '')
        rule.disabled = rule_dict.get('disabled', 'no') == 'yes'
        rule.comment = rule_dict.get('comment', '')
        rule.src_address = rule_dict.get('src_address', rule_dict.get('src-address', ''))
        rule.dst_address = rule_dict.get('dst_address', rule_dict.get('dst-address', ''))
        rule.src_address_list = rule_dict.get('src_address_list', rule_dict.get('src-address-list', ''))
        rule.dst_address_list = rule_dict.get('dst_address_list', rule_dict.get('dst-address-list', ''))
        rule.protocol = rule_dict.get('protocol', '')
        rule.dst_port = rule_dict.get('dst_port', rule_dict.get('dst-port', ''))
        rule.src_port = rule_dict.get('src_port', rule_dict.get('src-port', ''))
        rule.new_connection_mark = rule_dict.get('new_connection_mark', rule_dict.get('new-connection-mark', ''))
        rule.new_routing_mark = rule_dict.get('new_routing_mark', rule_dict.get('new-routing-mark', ''))
        rule.routing_mark = rule_dict.get('routing_mark', rule_dict.get('routing-mark', ''))
        rule.passthrough = rule_dict.get('passthrough', '')
        rule.other = {k: v for k, v in rule_dict.items() if k not in MANGLE_KNOWN_FIELDS}
        mangle_rules.append(rule)

    return mangle_rules
