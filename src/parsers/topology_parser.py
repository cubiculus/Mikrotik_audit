"""Parser for network topology: Bridge, WireGuard, PPP, ARP."""

import logging
import re
from typing import List, Optional

from src.models import BridgePort, WireGuardPeer, PPPActive, ARPEntry
from src.parsers.utils import parse_key_value_line

logger = logging.getLogger(__name__)


def parse_bridge_ports(results: List) -> List[BridgePort]:
    """
    Parse bridge port information from /interface bridge port print detail.

    Формат вывода RouterOS:
     0  bridge=bridge1 port=ether1 priority=128 path-cost=100
        edge=yes p2p=yes learning=yes hw=yes
    """
    ports: list[dict] = []

    if not results or results[0].has_error:
        logger.warning("No bridge port data available")
        return ports

    output = results[0].stdout

    # Парсинг многострочного формата
    current_port: Optional[dict] = None
    lines = output.split('\n')

    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue

        # Проверяем начало новой записи
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущий порт
            if current_port:
                ports.append(_create_bridge_port(current_port))

            # Начинаем новый порт
            current_port = {}
            rest = entry_match.group(3) or ''

            if '=' in rest:
                current_port.update(parse_key_value_line(rest))
            continue

        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_port is not None:
                current_port.update(parse_key_value_line(line))
            continue

    # Сохраняем последний порт
    if current_port:
        ports.append(_create_bridge_port(current_port))

    return ports


def _create_bridge_port(data: dict) -> BridgePort:
    """Create BridgePort object from dictionary."""
    port = BridgePort()
    port.bridge = data.get('bridge', '')
    port.port = data.get('port', '')

    try:
        port.priority = int(data.get('priority', '0'))
    except ValueError:
        pass

    try:
        port.path_cost = int(data.get('path_cost', '') or data.get('path-cost', '0'))
    except ValueError:
        pass

    port.edge = data.get('edge', '')
    port.p2p = data.get('p2p', '')
    port.learning = data.get('learning', 'yes') in ('yes', 'true')
    port.horizon = data.get('horizon', '')
    port.hw = data.get('hw', 'no') in ('yes', 'true')
    port.disabled = data.get('disabled', 'no') in ('yes', 'true')

    return port


def parse_wireguard_peers(results: List) -> List[WireGuardPeer]:
    """
    Parse WireGuard peer information from /interface wireguard peers print detail.

    Формат вывода RouterOS:
     0  interface=wg1 public-key="abc123..."
        endpoint-address=1.2.3.4 endpoint-port=51820
        allowed-address=192.168.10.0/24
        persistent-keepalive=25s
        last-handshake=5m ago
        tx-bytes=123456 rx-bytes=789012
    """
    peers: list[dict] = []

    if not results or results[0].has_error:
        logger.warning("No WireGuard peer data available")
        return peers

    output = results[0].stdout

    # Парсинг многострочного формата
    current_peer: Optional[dict] = None
    lines = output.split('\n')

    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue

        # Проверяем начало новой записи
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущего пира
            if current_peer:
                peers.append(_create_wireguard_peer(current_peer))

            # Начинаем нового пира
            current_peer = {}
            rest = entry_match.group(3) or ''

            if '=' in rest:
                current_peer.update(parse_key_value_line(rest))
            continue

        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_peer is not None:
                current_peer.update(parse_key_value_line(line))
            continue

    # Сохраняем последнего пира
    if current_peer:
        peers.append(_create_wireguard_peer(current_peer))

    return peers


def _create_wireguard_peer(data: dict) -> WireGuardPeer:
    """Create WireGuardPeer object from dictionary."""
    peer = WireGuardPeer()
    peer.interface = data.get('interface', '')
    peer.public_key = data.get('public_key', '') or data.get('public-key', '')
    peer.preshared_key = data.get('preshared_key', '') or data.get('preshared-key', '')
    peer.endpoint_address = data.get('endpoint_address', '') or data.get('endpoint-address', '')

    try:
        peer.endpoint_port = int(data.get('endpoint_port', '') or data.get('endpoint-port', '0'))
    except ValueError:
        pass

    peer.allowed_address = data.get('allowed_address', '') or data.get('allowed-address', '')

    # Parse persistent-keepalive (e.g., "25s" -> 25)
    pk = data.get('persistent_keepalive', '') or data.get('persistent-keepalive', '0')
    try:
        peer.persistent_keepalive = int(re.sub(r'[^\d]', '', pk) or '0')
    except ValueError:
        pass

    peer.last_handshake = data.get('last_handshake', '') or data.get('last-handshake', '')

    # Parse bytes
    tx = data.get('tx_bytes', '') or data.get('tx-bytes', '0')
    rx = data.get('rx_bytes', '') or data.get('rx-bytes', '0')
    try:
        peer.tx_bytes = int(re.sub(r'[^\d]', '', tx) or '0')
    except ValueError:
        pass
    try:
        peer.rx_bytes = int(re.sub(r'[^\d]', '', rx) or '0')
    except ValueError:
        pass

    peer.disabled = data.get('disabled', 'no') in ('yes', 'true')

    return peer


def parse_ppp_active(results: List) -> List[PPPActive]:
    """
    Parse active PPP connections from /ppp active print detail.

    Формат вывода RouterOS:
     0  user=admin address=192.168.88.2 service=l2tp
        caller-id=1.2.3.4 encoding=MPPE128
        connected-since=2h30m session-id=0x12345
        uptime=2h30m rate-tx=1000000 rate-rx=2000000
        total-tx=123456789 total-rx=987654321
    """
    connections: list[dict] = []

    if not results or results[0].has_error:
        logger.warning("No PPP active data available")
        return connections

    output = results[0].stdout

    # Парсинг многострочного формата
    current_conn: Optional[dict] = None
    lines = output.split('\n')

    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue

        # Проверяем начало новой записи
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущее соединение
            if current_conn:
                connections.append(_create_ppp_active(current_conn))

            # Начинаем новое соединение
            current_conn = {}
            rest = entry_match.group(3) or ''

            if '=' in rest:
                current_conn.update(parse_key_value_line(rest))
            continue

        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_conn is not None:
                current_conn.update(parse_key_value_line(line))
            continue

    # Сохраняем последнее соединение
    if current_conn:
        connections.append(_create_ppp_active(current_conn))

    return connections


def _create_ppp_active(data: dict) -> PPPActive:
    """Create PPPActive object from dictionary."""
    conn = PPPActive()
    conn.user = data.get('user', '')
    conn.address = data.get('address', '')
    conn.service = data.get('service', '')
    conn.caller_id = data.get('caller_id', '') or data.get('caller-id', '')
    conn.encoding = data.get('encoding', '')
    conn.connected_since = data.get('connected_since', '') or data.get('connected-since', '')
    conn.session_id = data.get('session_id', '') or data.get('session-id', '')
    conn.uptime = data.get('uptime', '')

    # Parse rates and totals
    try:
        rate_tx = data.get('rate_tx', '') or data.get('rate-tx', '0')
        conn.rate_tx = int(re.sub(r'[^\d]', '', rate_tx) or '0')
    except ValueError:
        pass

    try:
        rate_rx = data.get('rate_rx', '') or data.get('rate-rx', '0')
        conn.rate_rx = int(re.sub(r'[^\d]', '', rate_rx) or '0')
    except ValueError:
        pass

    try:
        total_tx = data.get('total_tx', '') or data.get('total-tx', '0')
        conn.total_tx = int(re.sub(r'[^\d]', '', total_tx) or '0')
    except ValueError:
        pass

    try:
        total_rx = data.get('total_rx', '') or data.get('total-rx', '0')
        conn.total_rx = int(re.sub(r'[^\d]', '', total_rx) or '0')
    except ValueError:
        pass

    return conn


def parse_arp(results: List) -> List[ARPEntry]:
    """
    Parse ARP table from /ip arp print detail.

    Формат вывода RouterOS:
     0  address=192.168.1.100 mac-address=AA:BB:CC:DD:EE:FF
        interface=ether1 status=completed dynamic=yes
    """
    entries: list[dict] = []

    if not results or results[0].has_error:
        logger.warning("No ARP data available")
        return entries

    output = results[0].stdout

    # Парсинг многострочного формата
    current_entry: Optional[dict] = None
    lines = output.split('\n')

    for line in lines:
        line = line.rstrip()
        if not line or line.strip().startswith('Flags:'):
            continue

        # Проверяем начало новой записи
        entry_match = re.match(r'^\s*(\d+)\s+(?:([A-Z*]+)\s+)?(.*)$', line)
        if entry_match:
            # Сохраняем предыдущую запись
            if current_entry:
                entries.append(_create_arp_entry(current_entry))

            # Начинаем новую запись
            current_entry = {}
            # Save flags if present (e.g., 'P' for published)
            flags = entry_match.group(2) or ''
            if flags:
                current_entry['flags'] = flags

            rest = entry_match.group(3) or ''

            if '=' in rest:
                current_entry.update(parse_key_value_line(rest))
            continue

        # Продолжение с отступом
        if (line.startswith('  ') or line.startswith('\t')) and '=' in line:
            if current_entry is not None:
                current_entry.update(parse_key_value_line(line))
            continue

    # Сохраняем последнюю запись
    if current_entry:
        entries.append(_create_arp_entry(current_entry))

    return entries


def _create_arp_entry(data: dict) -> ARPEntry:
    """Create ARPEntry object from dictionary."""
    entry = ARPEntry()
    entry.address = data.get('address', '')
    entry.mac_address = data.get('mac_address', '') or data.get('mac-address', '')
    entry.interface = data.get('interface', '')
    entry.status = data.get('status', '')
    entry.dynamic = data.get('dynamic', 'no') in ('yes', 'true')
    entry.published = data.get('published', 'no') in ('yes', 'true')

    # Check for 'P' flag in the raw flags field
    flags = data.get('flags', '')
    if 'P' in flags:
        entry.published = True

    return entry
