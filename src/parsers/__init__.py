"""Parsers package for MikroTik command outputs."""
from .interface_parser import parse_interface_stats
from .ip_parser import parse_ip_address_results
from .dhcp_parser import parse_dhcp_leases
from .container_parser import parse_containers
from .firewall_parser import parse_nat_rules, parse_filter_rules, parse_mangle_rules
from .routing_parser import parse_routes, parse_routing_rules, parse_dns_config
from .system_parser import (
    parse_system_resource,
    parse_system_health,
    parse_system_package,
    parse_system_package_update,
    parse_disks,
)
from .service_parser import (
    parse_ip_service,
    parse_ssh_sessions,
    parse_users,
    parse_certificates,
    parse_scripts,
    parse_scheduler,
)
from .topology_parser import (
    parse_bridge_ports,
    parse_wireguard_peers,
    parse_ppp_active,
    parse_arp,
)
from .diagnostic_parser import (
    parse_logs,
    parse_firewall_logs,
    parse_history,
    parse_ping_results,
)

__all__ = [
    'parse_interface_stats',
    'parse_ip_address_results',
    'parse_dhcp_leases',
    'parse_containers',
    'parse_nat_rules',
    'parse_filter_rules',
    'parse_mangle_rules',
    'parse_routes',
    'parse_routing_rules',
    'parse_dns_config',
    # System
    'parse_system_resource',
    'parse_system_health',
    'parse_system_package',
    'parse_system_package_update',
    'parse_disks',
    # Services
    'parse_ip_service',
    'parse_ssh_sessions',
    'parse_users',
    'parse_certificates',
    'parse_scripts',
    'parse_scheduler',
    # Topology
    'parse_bridge_ports',
    'parse_wireguard_peers',
    'parse_ppp_active',
    'parse_arp',
    # Diagnostics
    'parse_logs',
    'parse_firewall_logs',
    'parse_history',
    'parse_ping_results',
]
