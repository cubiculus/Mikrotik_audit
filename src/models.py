"""Data models for MikroTik audit results."""

from dataclasses import dataclass, field
from typing import Any


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
    # Additional fields for deep analysis (1.8)
    privileged: bool = False
    mounts: list = field(default_factory=list)  # List of mount points
    envs: list = field(default_factory=list)  # List of environment variables
    netmask: str = ""  # Container network mask
    bridge: str = ""  # Bridge interface name


@dataclass
class Disk:
    """Disk information"""
    name: str = ""
    type: str = ""
    path: str = ""
    total_size: int = 0  # in bytes
    free_size: int = 0  # in bytes
    used_percent: float = 0.0


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
    # System resources
    system_resource: Any = None
    system_health: Any = None
    disks: list = field(default_factory=list)
    packages: list = field(default_factory=list)
    package_update: dict = field(default_factory=dict)
    # Services
    services: list = field(default_factory=list)
    ssh_sessions: list = field(default_factory=list)
    users: list = field(default_factory=list)
    certificates: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    schedulers: list = field(default_factory=list)
    # Topology
    bridge_ports: list = field(default_factory=list)
    wireguard_peers: list = field(default_factory=list)
    ppp_active: list = field(default_factory=list)
    arp_entries: list = field(default_factory=list)
    # Diagnostics
    logs: list = field(default_factory=list)
    firewall_logs: list = field(default_factory=list)
    history: list = field(default_factory=list)
    ping_results: dict = field(default_factory=dict)


@dataclass
class SystemResource:
    """System resource information"""
    uptime: str = ""
    version: str = ""
    build_time: str = ""
    board_name: str = ""
    architecture: str = ""
    cpu_count: int = 1
    cpu_load: list = field(default_factory=list)  # [core1%, core2%, ...]
    free_memory: int = 0
    total_memory: int = 0
    free_hdd: int = 0
    total_hdd: int = 0
    write_sectors_since_reboot: int = 0
    bad_blocks: int = 0
    bad_blocks_percent: float = 0.0
    factory_firmware: str = ""
    current_firmware: str = ""
    upgrade_firmware: str = ""
    temperature: str = ""
    voltage: str = ""
    psu1_state: str = ""
    psu2_state: str = ""
    psu1_voltage: str = ""
    psu2_voltage: str = ""
    fan1_speed: str = ""
    fan2_speed: str = ""
    fan_state: str = ""
    poe_out_state: str = ""
    board_temperature1: str = ""
    board_temperature2: str = ""
    junction_temperature: str = ""
    heap_size: int = 0
    free_heap: int = 0
    architecture_name: str = ""
    platform: str = ""


@dataclass
class Service:
    """Network service information (SSH, FTP, Winbox, etc.)"""
    name: str = ""
    port: int = 0
    disabled: bool = False
    tls_required: bool = False
    address: str = ""  # IP address filter
    comment: str = ""


@dataclass
class SSHSession:
    """Active SSH session information"""
    user: str = ""
    remote_address: str = ""
    remote_port: int = 0
    connected_since: str = ""
    encoding: str = ""
    client: str = ""


@dataclass
class Certificate:
    """System certificate information"""
    name: str = ""
    common_name: str = ""
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    valid_from: str = ""
    valid_until: str = ""
    expired: bool = False
    revoked: bool = False
    trusted: bool = False
    key_type: str = ""
    key_size: int = 0
    fingerprint: str = ""
    comment: str = ""


@dataclass
class Script:
    """System script information"""
    name: str = ""
    owner: str = ""
    policy: list = field(default_factory=list)
    dont_require_permissions: bool = False
    source: str = ""
    last_modified: str = ""


@dataclass
class Scheduler:
    """System scheduler task information"""
    name: str = ""
    start_date: str = ""
    start_time: str = ""
    interval: str = ""
    run_count: int = 0
    last_run: str = ""
    next_run: str = ""
    on_event: str = ""
    script: str = ""
    disabled: bool = False
    comment: str = ""


@dataclass
class BridgePort:
    """Bridge port information"""
    bridge: str = ""
    port: str = ""
    priority: int = 0
    path_cost: int = 0
    edge: str = ""
    p2p: str = ""
    learning: bool = True
    horizon: str = ""
    hw: bool = False
    disabled: bool = False


@dataclass
class WireGuardPeer:
    """WireGuard peer information"""
    interface: str = ""
    public_key: str = ""
    preshared_key: str = ""
    endpoint_address: str = ""
    endpoint_port: int = 0
    allowed_address: str = ""
    persistent_keepalive: int = 0
    last_handshake: str = ""
    tx_bytes: int = 0
    rx_bytes: int = 0
    disabled: bool = False


@dataclass
class PPPActive:
    """Active PPP connection information"""
    user: str = ""
    address: str = ""
    service: str = ""  # l2tp, pptp, ovpn, sstp
    caller_id: str = ""
    encoding: str = ""
    connected_since: str = ""
    session_id: str = ""
    uptime: str = ""
    rate_tx: int = 0
    rate_rx: int = 0
    total_tx: int = 0
    total_rx: int = 0


@dataclass
class ARPEntry:
    """ARP table entry information"""
    address: str = ""
    mac_address: str = ""
    interface: str = ""
    status: str = ""  # completed, failed, published
    dynamic: bool = False
    published: bool = False


@dataclass
class LogEntry:
    """Log entry information"""
    time: str = ""
    topics: str = ""
    message: str = ""
    prefix: str = ""


@dataclass
class HistoryEntry:
    """System history entry (configuration changes)"""
    time: str = ""
    action: str = ""
    by: str = ""
    cmd: str = ""


@dataclass
class SystemHealth:
    """System health information"""
    temperature: str = ""
    voltage: str = ""
    current: str = ""
    psu1_state: str = ""
    psu2_state: str = ""
    psu1_voltage: str = ""
    psu2_voltage: str = ""
    fan1_speed: str = ""
    fan2_speed: str = ""
    poe_out_state: str = ""
    poe_out_current: str = ""
    board_temperature1: str = ""
    board_temperature2: str = ""
    junction_temperature: str = ""


@dataclass
class User:
    """User account information"""
    name: str = ""
    group: str = ""
    address: str = ""
    netmask: str = ""
    disabled: bool = False
    expired: bool = False
    last_logged_in: str = ""
    comment: str = ""


@dataclass
class Package:
    """System package information"""
    name: str = ""
    version: str = ""
    build_time: str = ""
    scheduled: bool = False
    disabled: bool = False
