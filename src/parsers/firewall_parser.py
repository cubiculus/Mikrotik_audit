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
    """Кэшированная функция для парсинга строки правила в словарь.

    Handles values with spaces by respecting quoted strings.
    """
    # Remove leading whitespace from RouterOS v7 format
    line = line.lstrip()

    rule_dict = {}
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
            # Quoted value
            value_start = i + 1
            i = value_start
            while i < n and line[i] != '"':
                i += 1
            value = line[value_start:i]
            i += 1  # Skip closing quote
        else:
            # Unquoted value (read until next whitespace)
            value_start = i
            while i < n and not line[i].isspace():
                i += 1
            value = line[value_start:i]

        rule_dict[key] = value

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
            # Process output line by line to handle comments
            lines = r.stdout.split('\n')
            i = 0
            while i < len(lines):
                line = lines[i].lstrip()

                # Skip empty lines
                if not line:
                    i += 1
                    continue

                # Check if this is a comment line (starts with ';;')
                if line.startswith(';;'):
                    # Save as comment for the next rule
                    comment_text = line[2:].strip()  # Remove ';; ' and whitespace
                    i += 1
                    # Next line should be the actual rule
                    if i < len(lines):
                        next_line = lines[i].lstrip()
                        if next_line and 'action=' in next_line:
                            rule_dict = _parse_rule_line(next_line)
                            if 'comment=' not in rule_dict and comment_text:
                                rule_dict['comment'] = comment_text
                            nat_rules.append(rule_dict)
                            i += 1
                    continue

                # If line contains action=, it's a rule
                if 'action=' in line:
                    rule_dict = _parse_rule_line(line)
                    nat_rules.append(rule_dict)
                i += 1
    return nat_rules


def parse_filter_rules(results: List) -> List[FilterRule]:
    """Parse Filter firewall rules."""
    filter_rules = []
    for r in results:
        if r.command.startswith(COMMAND_PATTERN_FILTER):
            # Process output line by line to handle comments
            lines = r.stdout.split('\n')
            i = 0
            while i < len(lines):
                line = lines[i].lstrip()

                # Skip empty lines
                if not line:
                    i += 1
                    continue

                # Check if this is a comment line (starts with ';;')
                if line.startswith(';;'):
                    # Save as comment for the next rule
                    comment_text = line[2:].strip()  # Remove ';; ' and whitespace
                    i += 1
                    # Next line should be the actual rule
                    if i < len(lines):
                        next_line = lines[i].lstrip()
                        if next_line and 'action=' in next_line:
                            rule_dict = _parse_rule_line(next_line)
                            if 'comment=' not in rule_dict and comment_text:
                                rule_dict['comment'] = comment_text
                            filter_rules.append(rule_dict)
                            i += 1
                    continue

                # If line contains action=, it's a rule
                if 'action=' in line:
                    rule_dict = _parse_rule_line(line)
                    filter_rules.append(rule_dict)
                i += 1
    return filter_rules


def parse_mangle_rules(results: List) -> List[MangleRule]:
    """Parse Mangle firewall rules."""
    mangle_rules = []
    for r in results:
        if r.command.startswith(COMMAND_PATTERN_MANGLE):
            # Process output line by line to handle comments
            lines = r.stdout.split('\n')
            i = 0
            while i < len(lines):
                line = lines[i].lstrip()

                # Skip empty lines
                if not line:
                    i += 1
                    continue

                # Check if this is a comment line (starts with ';;')
                if line.startswith(';;'):
                    # Save as comment for the next rule
                    comment_text = line[2:].strip()  # Remove ';; ' and whitespace
                    i += 1
                    # Next line should be the actual rule
                    if i < len(lines):
                        next_line = lines[i].lstrip()
                        if next_line and ('action=' in next_line or 'chain=' in next_line):
                            rule_dict = _parse_rule_line(next_line)
                            if 'comment=' not in rule_dict and comment_text:
                                rule_dict['comment'] = comment_text
                            mangle_rules.append(rule_dict)
                            i += 1
                    continue

                # If line contains action= or chain=, it's a rule
                if 'action=' in line or 'chain=' in line:
                    rule_dict = _parse_rule_line(line)
                    mangle_rules.append(rule_dict)
                i += 1
    return mangle_rules