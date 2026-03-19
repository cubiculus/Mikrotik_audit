"""Parser for MikroTik command outputs."""

import logging
import hashlib
import json
from pathlib import Path
from typing import List, Any, Optional
from collections import OrderedDict
from threading import Lock

from src.config import CommandResult
from src.models import NetworkOverview
from src.parsers import (
    parse_interface_stats,
    parse_ip_address_results,
    parse_dhcp_leases,
    parse_containers,
    parse_nat_rules,
    parse_filter_rules,
    parse_mangle_rules,
    parse_routes,
    parse_routing_rules,
    parse_dns_config,
    parse_system_resource,
    parse_system_health,
    parse_system_package,
    parse_system_package_update,
    parse_ip_service,
    parse_ssh_sessions,
    parse_users,
    parse_certificates,
    parse_scripts,
    parse_scheduler,
    parse_bridge_ports,
    parse_wireguard_peers,
    parse_ppp_active,
    parse_arp,
    parse_logs,
    parse_firewall_logs,
    parse_history,
    parse_ping_results,
    parse_disks,
)

logger = logging.getLogger(__name__)


class DataParser:
    """Parser for MikroTik command outputs - orchestrates all parsers with caching support."""

    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize parser with optional cache directory."""
        self.cache_dir = cache_dir or Path(".cache")
        self.cache_dir.mkdir(exist_ok=True)
        # Use OrderedDict for O(1) LRU operations
        self._memory_cache: OrderedDict[str, Any] = OrderedDict()
        self._max_cache_size = 100
        # Thread-safe lock for cache operations
        self._cache_lock = Lock()

    def _get_cache_key(self, command_output: str) -> str:
        """Generate cache key based on content using SHA256."""
        return hashlib.sha256(command_output.encode()).hexdigest()

    def _get_from_cache(self, cache_key: str) -> Any:
        """Retrieve data from cache with O(1) operations and thread safety."""
        with self._cache_lock:
            if cache_key in self._memory_cache:
                # Move to end to mark as recently used (O(1) with OrderedDict)
                self._memory_cache.move_to_end(cache_key)
                logger.debug(f"Cache hit (memory): {cache_key[:8]}")
                return self._memory_cache[cache_key]

        # Check disk cache outside of lock (file I/O is slow)
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            logger.debug(f"Cache hit (disk): {cache_key[:8]}")
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None

    def _save_to_cache(self, cache_key: str, data: Any, persist: bool = False) -> None:
        """Save data to cache with O(1) LRU eviction and thread safety."""
        # Memory cache with LRU eviction using OrderedDict (thread-safe)
        with self._cache_lock:
            if cache_key not in self._memory_cache and len(self._memory_cache) >= self._max_cache_size:
                # Evict least recently used item (first item in OrderedDict)
                lru_key = next(iter(self._memory_cache))
                del self._memory_cache[lru_key]
                logger.debug(f"Evicted LRU cache entry: {lru_key[:8]}")

            # Update access order - move to end if exists, or add to end
            self._memory_cache[cache_key] = data
            self._memory_cache.move_to_end(cache_key)

        # Disk cache if persist is True (outside of lock to avoid blocking)
        if persist:
            cache_file = self.cache_dir / f"{cache_key}.json"
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)

    def build_network_overview(self, results: List[CommandResult]) -> NetworkOverview:
        """Aggregate network overview from all command results with caching."""
        overview = NetworkOverview()

        # Index results by commands for efficient lookup
        results_by_command = {}
        for r in results:
            if not r.has_error:
                results_by_command[r.command] = r

        # Parse system version with caching
        if '/system resource print' in results_by_command:
            cache_key = self._get_cache_key(results_by_command['/system resource print'].stdout)
            cached = self._get_from_cache(cache_key)
            if cached:
                overview.system_version = cached
                logger.debug("Using cached system version")
            else:
                for line in results_by_command['/system resource print'].stdout.split('\n'):
                    if 'version:' in line or 'version=' in line:
                        if 'version:' in line:
                            overview.system_version = line.split('version:')[1].strip()
                        elif 'version=' in line:
                            overview.system_version = line.split('version=')[1].strip()
                        break
                self._save_to_cache(cache_key, overview.system_version, persist=True)

        # Parse system identity with caching
        if '/system identity print' in results_by_command:
            cache_key = self._get_cache_key(results_by_command['/system identity print'].stdout)
            cached = self._get_from_cache(cache_key)
            if cached:
                overview.system_identity = cached
                logger.debug("Using cached system identity")
            else:
                for line in results_by_command['/system identity print'].stdout.split('\n'):
                    if 'name:' in line or 'name=' in line:
                        if 'name:' in line:
                            overview.system_identity = line.split('name:')[1].strip()
                        elif 'name=' in line:
                            overview.system_identity = line.split('name=')[1].strip()
                        break
                self._save_to_cache(cache_key, overview.system_identity, persist=True)

        # Parse interfaces with caching
        iface_results = [r for r in results if r.command.startswith('/interface')]
        if iface_results:
            iface_output = '\n'.join([r.stdout for r in iface_results])
            cache_key = self._get_cache_key(f"interfaces:{iface_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                overview.interfaces = cached['interfaces']
                overview.total_interfaces = cached['total_interfaces']
                overview.active_interfaces = cached['active_interfaces']
                logger.debug("Using cached interface data")
            else:
                interfaces, iface_overview = parse_interface_stats(iface_results)
                overview.interfaces = interfaces
                overview.total_interfaces = iface_overview.total_interfaces
                overview.active_interfaces = iface_overview.active_interfaces
                # Convert dataclass objects to dictionaries for JSON serialization
                interfaces_dict = [
                    iface.__dict__ if hasattr(iface, '__dict__') else iface
                    for iface in interfaces
                ]
                self._save_to_cache(cache_key, {
                    'interfaces': interfaces_dict,
                    'total_interfaces': iface_overview.total_interfaces,
                    'active_interfaces': iface_overview.active_interfaces
                }, persist=True)

        # Parse IP addresses with caching
        ip_results = [r for r in results if r.command.startswith('/ip address')]
        if ip_results:
            ip_output = '\n'.join([r.stdout for r in ip_results])
            cache_key = self._get_cache_key(f"ip_addresses:{ip_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                from src.models import IPAddress
                overview.ip_addresses = [IPAddress(**ip) for ip in cached['ip_addresses']]
                overview.total_ip_addresses = cached['total_ip_addresses']
                logger.debug("Using cached IP address data")
            else:
                ip_addresses, ip_overview = parse_ip_address_results(ip_results)
                overview.ip_addresses = ip_addresses
                overview.total_ip_addresses = ip_overview.total_ip_addresses
                self._save_to_cache(cache_key, {
                    'ip_addresses': [ip.__dict__ for ip in ip_addresses],
                    'total_ip_addresses': ip_overview.total_ip_addresses
                }, persist=True)

        # Parse DHCP leases with caching
        dhcp_results = [r for r in results if r.command.startswith('/ip dhcp-server lease')]
        if dhcp_results:
            dhcp_output = '\n'.join([r.stdout for r in dhcp_results])
            cache_key = self._get_cache_key(f"dhcp_leases:{dhcp_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                from src.models import DHCPLease
                overview.dhcp_leases = [DHCPLease(**lease) for lease in cached['dhcp_leases']]
                overview.dhcp_leases_count = cached['dhcp_leases_count']
                overview.dhcp_active_leases = cached['dhcp_active_leases']
                logger.debug("Using cached DHCP lease data")
            else:
                dhcp_leases, dhcp_overview = parse_dhcp_leases(dhcp_results)
                overview.dhcp_leases = dhcp_leases
                overview.dhcp_leases_count = dhcp_overview.dhcp_leases_count
                overview.dhcp_active_leases = dhcp_overview.dhcp_active_leases
                self._save_to_cache(cache_key, {
                    'dhcp_leases': [lease.__dict__ for lease in dhcp_leases],
                    'dhcp_leases_count': dhcp_overview.dhcp_leases_count,
                    'dhcp_active_leases': dhcp_overview.dhcp_active_leases
                }, persist=True)

        # Parse containers with caching
        container_results = [r for r in results if r.command.startswith('/container')]
        if container_results:
            container_output = '\n'.join([r.stdout for r in container_results])
            cache_key = self._get_cache_key(f"containers:{container_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                from src.models import Container
                overview.containers = [Container(**c) for c in cached['containers']]
                overview.containers_total = cached['containers_total']
                overview.containers_running = cached['containers_running']
                logger.debug("Using cached container data")
            else:
                containers, containers_overview = parse_containers(container_results)
                overview.containers = containers
                overview.containers_total = containers_overview.containers_total
                overview.containers_running = containers_overview.containers_running
                self._save_to_cache(cache_key, {
                    'containers': [c.__dict__ for c in containers],
                    'containers_total': containers_overview.containers_total,
                    'containers_running': containers_overview.containers_running
                }, persist=True)

        # Parse DNS info with caching
        dns_output = '\n'.join([r.stdout for r in results if '/ip dns' in r.command])
        if dns_output:
            cache_key = self._get_cache_key(f"dns:{dns_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                from src.models import DNSInfo
                overview.dns = DNSInfo(**cached)
                logger.debug("Using cached DNS data")
            else:
                overview.dns = parse_dns_config(results)
                self._save_to_cache(cache_key, overview.dns.__dict__, persist=True)

        # Parse routing rules with caching
        routing_output = '\n'.join([r.stdout for r in results if '/ip route' in r.command or '/routing' in r.command])
        if routing_output:
            cache_key = self._get_cache_key(f"routing_rules:{routing_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                # parse_routing_rules returns List[dict], so restore as-is
                overview.routing_rules = [r for r in cached]
                logger.debug("Using cached routing rules")
            else:
                overview.routing_rules = parse_routing_rules(results)
                self._save_to_cache(cache_key, overview.routing_rules, persist=True)

        # Parse routes with caching
        routes_output = '\n'.join([r.stdout for r in results if '/ip route' in r.command])
        if routes_output:
            cache_key = self._get_cache_key(f"routes:{routes_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                from src.models import Route
                overview.routes = [Route(**r) for r in cached]
                logger.debug("Using cached routes")
            else:
                overview.routes = parse_routes(results)
                self._save_to_cache(cache_key, [r.__dict__ for r in overview.routes], persist=True)

        # Parse mangle rules with caching
        mangle_output = '\n'.join([r.stdout for r in results if '/ip firewall mangle' in r.command])
        if mangle_output:
            cache_key = self._get_cache_key(f"mangle_rules:{mangle_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                from src.models import MangleRule
                overview.mangle_rules = [MangleRule(**r) for r in cached]
                logger.debug("Using cached mangle rules")
            else:
                overview.mangle_rules = parse_mangle_rules(results)
                self._save_to_cache(cache_key, [r.__dict__ for r in overview.mangle_rules], persist=True)

        # Parse NAT rules with caching
        nat_output = '\n'.join([r.stdout for r in results if '/ip firewall nat' in r.command])
        if nat_output:
            cache_key = self._get_cache_key(f"nat_rules:{nat_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                from src.models import NATRule
                overview.nat_rules = [NATRule(**r) for r in cached]
                logger.debug("Using cached NAT rules")
            else:
                overview.nat_rules = parse_nat_rules(results)
                self._save_to_cache(cache_key, [r.__dict__ for r in overview.nat_rules], persist=True)

        # Parse Filter rules with caching
        filter_output = '\n'.join([r.stdout for r in results if '/ip firewall filter' in r.command])
        if filter_output:
            cache_key = self._get_cache_key(f"filter_rules:{filter_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                from src.models import FilterRule
                overview.filter_rules = [FilterRule(**r) for r in cached]
                logger.debug("Using cached filter rules")
            else:
                overview.filter_rules = parse_filter_rules(results)
                self._save_to_cache(cache_key, [r.__dict__ for r in overview.filter_rules], persist=True)

        # Parse system resources
        resource_results = [r for r in results if r.command == '/system resource print']
        if resource_results:
            overview.system_resource = parse_system_resource(resource_results)

        # Parse disks
        disk_results = [r for r in results if r.command.startswith('/disk')]
        if disk_results:
            overview.disks = parse_disks(disk_results)

        # Parse system health
        health_results = [r for r in results if r.command == '/system health print']
        if health_results:
            overview.system_health = parse_system_health(health_results)

        # Parse packages
        package_results = [r for r in results if r.command == '/system package print']
        if package_results:
            overview.packages = parse_system_package(package_results)

        # Parse package update
        update_results = [r for r in results if r.command == '/system package update print']
        if update_results:
            overview.package_update = parse_system_package_update(update_results)

        # Parse services
        service_results = [r for r in results if r.command.startswith('/ip service')]
        if service_results:
            overview.services = parse_ip_service(service_results)

        # Parse SSH sessions
        ssh_results = [r for r in results if r.command.startswith('/ip ssh')]
        if ssh_results:
            overview.ssh_sessions = parse_ssh_sessions(ssh_results)

        # Parse users
        user_results = [r for r in results if r.command.startswith('/user')]
        if user_results:
            overview.users = parse_users(user_results)

        # Parse certificates
        cert_results = [r for r in results if r.command.startswith('/system certificate')]
        if cert_results:
            overview.certificates = parse_certificates(cert_results)

        # Parse scripts
        script_results = [r for r in results if r.command.startswith('/system script')]
        if script_results:
            overview.scripts = parse_scripts(script_results)

        # Parse schedulers
        scheduler_results = [r for r in results if r.command.startswith('/system scheduler')]
        if scheduler_results:
            overview.schedulers = parse_scheduler(scheduler_results)

        # Parse bridge ports
        bridge_results = [r for r in results if r.command.startswith('/interface bridge port')]
        if bridge_results:
            overview.bridge_ports = parse_bridge_ports(bridge_results)

        # Parse WireGuard peers
        wg_results = [r for r in results if r.command.startswith('/interface wireguard peers')]
        if wg_results:
            overview.wireguard_peers = parse_wireguard_peers(wg_results)

        # Parse PPP active
        ppp_results = [r for r in results if r.command.startswith('/ppp active')]
        if ppp_results:
            overview.ppp_active = parse_ppp_active(ppp_results)

        # Parse ARP
        arp_results = [r for r in results if r.command.startswith('/ip arp')]
        if arp_results:
            overview.arp_entries = parse_arp(arp_results)

        # Parse logs
        log_results = [r for r in results if r.command.startswith('/log print') and 'firewall' not in r.command]
        if log_results:
            overview.logs = parse_logs(log_results, count=50)

        # Parse firewall logs
        fw_log_results = [r for r in results if 'firewall' in r.command and r.command.startswith('/log')]
        if fw_log_results:
            overview.firewall_logs = parse_firewall_logs(fw_log_results)

        # Parse history
        history_results = [r for r in results if r.command.startswith('/system history')]
        if history_results:
            overview.history = parse_history(history_results)

        # Parse ping results
        ping_results_list = [r for r in results if r.command.startswith('/ping')]
        if ping_results_list:
            overview.ping_results = parse_ping_results(ping_results_list)

        return overview
