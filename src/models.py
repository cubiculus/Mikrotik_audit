"""Data models for MikroTik audit results."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Route:
    """Route information"""
    dst_address: str = ""
    gateway: str = ""
    routing_mark: str = ""
    disabled: bool = False
    distance: str = ""
    comment: str = ""
    other: dict = field(default_factory=dict)


@dataclass
class DNSInfo:
    """DNS configuration information"""
    servers: list = field(default_factory=list)
    use_doh: bool = False
    doh_server: str = ""
    static_entries: list = field(default_factory=list)
    allow_remote: bool = False
    cache_size: int = 0


@dataclass
class MangleRule:
    """Mangle firewall rule information"""
    action: str = ""
    chain: str = ""
    disabled: bool = False
    comment: str = ""
    src_address: str = ""
    dst_address: str = ""
    src_address_list: str = ""
    dst_address_list: str = ""
    protocol: str = ""
    dst_port: str = ""
    src_port: str = ""
    new_connection_mark: str = ""
    new_routing_mark: str = ""
    routing_mark: str = ""
    passthrough: str = ""
    other: dict = field(default_factory=dict)


@dataclass
class NATRule:
    """NAT firewall rule information"""
    chain: str = ""
    action: str = ""
    disabled: bool = False
    comment: str = ""
    src_address: str = ""
    dst_address: str = ""
    src_address_list: str = ""
    dst_address_list: str = ""
    protocol: str = ""
    src_port: str = ""
    dst_port: str = ""
    to_addresses: str = ""
    to_ports: str = ""
    out_interface: str = ""
    in_interface: str = ""
    in_interface_list: str = ""
    routing_mark: str = ""
    log: str = ""
    other: dict = field(default_factory=dict)


@dataclass
class FilterRule:
    """Filter firewall rule information"""
    chain: str = ""
    action: str = ""
    disabled: bool = False
    comment: str = ""
    src_address: str = ""
    dst_address: str = ""
    src_address_list: str = ""
    dst_address_list: str = ""
    protocol: str = ""
    src_port: str = ""
    dst_port: str = ""
    in_interface: str = ""
    out_interface: str = ""
    in_interface_list: str = ""
    out_interface_list: str = ""
    connection_state: str = ""
    connection_nat_state: str = ""
    connection_type: str = ""
    log: str = ""
    log_prefix: str = ""
    packet_mark: str = ""
    connection_mark: str = ""
    routing_mark: str = ""
    other: dict = field(default_factory=dict)


@dataclass
class NetworkInterface:
    """Network interface information"""
    name: str = ""
    type: str = ""
    mtu: int = 0
    running: bool = False
    disabled: bool = False
    rx_byte: int = 0
    tx_byte: int = 0
    rx_packet: int = 0
    tx_packet: int = 0
    mac_address: str = ""


@dataclass
class IPAddress:
    """IP address information"""
    address: str = ""
    network: str = ""
    interface: str = ""
    actual_interface: str = ""
    comment: str = ""


@dataclass
class DHCPLease:
    """DHCP lease information"""
    address: str = ""
    mac_address: str = ""
    client_hostname: str = ""
    host_name: str = ""
    address_lists: str = ""
    lease_status: str = ""  # Will be "Static" or "Dynamic"
    expires_after: str = ""
    last_seen: str = ""
    server: str = ""
    # Single boolean field for dynamic vs static
    # True = dynamic lease, False = static lease
    dynamic: bool = False
    comment: str = ""


@dataclass
class Container:
    """Container information for Docker/Virtualization"""
    name: str = ""
    image: str = ""
    status: str = ""
    root_directory: str = ""
    root_dir: str = ""  # for compatibility with report_generator.py
    interface: str = ""  # for compatibility with report_generator.py
    ip_address: str = ""
    created: str = ""
    started: str = ""
    uptime: str = ""


@dataclass
class NetworkOverview:
    """Network overview statistics"""
    total_interfaces: int = 0
    active_interfaces: int = 0
    total_ip_addresses: int = 0
    dhcp_leases_count: int = 0
    dhcp_active_leases: int = 0
    containers_running: int = 0
    containers_total: int = 0
    # For report_generator.py compatibility
    interfaces: list = field(default_factory=list)
    ip_addresses: list = field(default_factory=list)
    dhcp_leases: list = field(default_factory=list)
    containers: list = field(default_factory=list)
    dns: Any = None
    mangle_rules: list = field(default_factory=list)
    routing_rules: list = field(default_factory=list)
    routes: list = field(default_factory=list)
    address_lists: dict = field(default_factory=dict)
    nat_rules: list = field(default_factory=list)
    filter_rules: list = field(default_factory=list)
    system_identity: str = ""
    system_version: str = ""