"""Parser for MikroTik command outputs."""

import logging
import hashlib
import pickle
from functools import lru_cache
from pathlib import Path
from typing import List, Any, Dict, Optional

from src.config import CommandResult, RouterInfo, SecurityIssue
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
)

logger = logging.getLogger(__name__)


class DataParser:
    """Parser for MikroTik command outputs - orchestrates all parsers with caching support."""

    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize parser with optional cache directory."""
        self.cache_dir = cache_dir or Path(".cache")
        self.cache_dir.mkdir(exist_ok=True)
        self._memory_cache: dict[str, Any] = {}
        self._cache_access_order: list[str] = []  # Для LRU eviction

    def _get_cache_key(self, command_output: str) -> str:
        """Generate cache key based on content using SHA256."""
        return hashlib.sha256(command_output.encode()).hexdigest()

    def _get_from_cache(self, cache_key: str):
        """Retrieve data from cache."""
        if cache_key in self._memory_cache:
            # Update access order for LRU
            if cache_key in self._cache_access_order:
                self._cache_access_order.remove(cache_key)
            self._cache_access_order.append(cache_key)
            logger.debug(f"Cache hit (memory): {cache_key[:8]}")
            return self._memory_cache[cache_key]

        cache_file = self.cache_dir / f"{cache_key}.pkl"
        if cache_file.exists():
            logger.debug(f"Cache hit (disk): {cache_key[:8]}")
            with open(cache_file, 'rb') as f:
                return pickle.load(f)
        return None

    def _save_to_cache(self, cache_key: str, data, persist: bool = False):
        """Save data to cache with LRU eviction policy."""
        # Memory cache with LRU eviction
        max_cache_size = 100
        if cache_key not in self._memory_cache and len(self._memory_cache) >= max_cache_size:
            # Evict least recently used item
            if self._cache_access_order:
                lru_key = self._cache_access_order.pop(0)
                if lru_key in self._memory_cache:
                    del self._memory_cache[lru_key]
                    logger.debug(f"Evicted LRU cache entry: {lru_key[:8]}")
        
        # Update access order
        if cache_key in self._cache_access_order:
            self._cache_access_order.remove(cache_key)
        self._cache_access_order.append(cache_key)
        
        self._memory_cache[cache_key] = data

        # Disk cache if persist is True
        if persist:
            cache_file = self.cache_dir / f"{cache_key}.pkl"
            with open(cache_file, 'wb') as f:
                pickle.dump(data, f)

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
                self._save_to_cache(cache_key, {
                    'interfaces': interfaces,
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
                overview.ip_addresses = cached['ip_addresses']
                overview.total_ip_addresses = cached['total_ip_addresses']
                logger.debug("Using cached IP address data")
            else:
                ip_addresses, ip_overview = parse_ip_address_results(ip_results)
                overview.ip_addresses = ip_addresses
                overview.total_ip_addresses = ip_overview.total_ip_addresses
                self._save_to_cache(cache_key, {
                    'ip_addresses': ip_addresses,
                    'total_ip_addresses': ip_overview.total_ip_addresses
                }, persist=True)

        # Parse DHCP leases with caching
        dhcp_results = [r for r in results if r.command.startswith('/ip dhcp-server lease')]
        if dhcp_results:
            dhcp_output = '\n'.join([r.stdout for r in dhcp_results])
            cache_key = self._get_cache_key(f"dhcp_leases:{dhcp_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                overview.dhcp_leases = cached['dhcp_leases']
                overview.dhcp_leases_count = cached['dhcp_leases_count']
                overview.dhcp_active_leases = cached['dhcp_active_leases']
                logger.debug("Using cached DHCP lease data")
            else:
                dhcp_leases, dhcp_overview = parse_dhcp_leases(dhcp_results)
                for lease in dhcp_leases:
                    if not hasattr(lease, 'dynamic'):
                        lease.dynamic = getattr(lease, 'dynamic_entry', False)
                overview.dhcp_leases = dhcp_leases
                overview.dhcp_leases_count = dhcp_overview.dhcp_leases_count
                overview.dhcp_active_leases = dhcp_overview.dhcp_active_leases
                self._save_to_cache(cache_key, {
                    'dhcp_leases': dhcp_leases,
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
                overview.containers = cached['containers']
                overview.containers_total = cached['containers_total']
                overview.containers_running = cached['containers_running']
                logger.debug("Using cached container data")
            else:
                containers, containers_overview = parse_containers(container_results)
                overview.containers = containers
                overview.containers_total = containers_overview.containers_total
                overview.containers_running = containers_overview.containers_running
                self._save_to_cache(cache_key, {
                    'containers': containers,
                    'containers_total': containers_overview.containers_total,
                    'containers_running': containers_overview.containers_running
                }, persist=True)

        # Parse DNS info with caching
        dns_output = '\n'.join([r.stdout for r in results if '/ip dns' in r.command])
        if dns_output:
            cache_key = self._get_cache_key(f"dns:{dns_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                overview.dns = cached
                logger.debug("Using cached DNS data")
            else:
                overview.dns = parse_dns_config(results)
                self._save_to_cache(cache_key, overview.dns, persist=True)

        # Parse routing rules with caching
        routing_output = '\n'.join([r.stdout for r in results if '/ip route' in r.command or '/routing' in r.command])
        if routing_output:
            cache_key = self._get_cache_key(f"routing_rules:{routing_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                overview.routing_rules = cached
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
                overview.routes = cached
                logger.debug("Using cached routes")
            else:
                overview.routes = parse_routes(results)
                self._save_to_cache(cache_key, overview.routes, persist=True)

        # Parse mangle rules with caching
        mangle_output = '\n'.join([r.stdout for r in results if '/ip firewall mangle' in r.command])
        if mangle_output:
            cache_key = self._get_cache_key(f"mangle_rules:{mangle_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                overview.mangle_rules = cached
                logger.debug("Using cached mangle rules")
            else:
                overview.mangle_rules = parse_mangle_rules(results)
                self._save_to_cache(cache_key, overview.mangle_rules, persist=True)

        # Parse NAT rules with caching
        nat_output = '\n'.join([r.stdout for r in results if '/ip firewall nat' in r.command])
        if nat_output:
            cache_key = self._get_cache_key(f"nat_rules:{nat_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                overview.nat_rules = cached
                logger.debug("Using cached NAT rules")
            else:
                overview.nat_rules = parse_nat_rules(results)
                self._save_to_cache(cache_key, overview.nat_rules, persist=True)

        # Parse Filter rules with caching
        filter_output = '\n'.join([r.stdout for r in results if '/ip firewall filter' in r.command])
        if filter_output:
            cache_key = self._get_cache_key(f"filter_rules:{filter_output}")
            cached = self._get_from_cache(cache_key)
            if cached:
                overview.filter_rules = cached
                logger.debug("Using cached filter rules")
            else:
                overview.filter_rules = parse_filter_rules(results)
                self._save_to_cache(cache_key, overview.filter_rules, persist=True)
        
        return overview
    
    @staticmethod
    def parse_key_value(output: str) -> Dict[str, Any]:
        """Parse simple key=value format"""
        result = {}
        for line in output.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                result[key.strip()] = value.strip()
        return result
    
    @staticmethod
    def parse_security_findings(results: List[CommandResult]) -> List[SecurityIssue]:
        """Parse security findings from various commands"""
        issues: List[SecurityIssue] = []

        for result in results:
            if result.has_error:
                continue

            if result.command in ['/ip firewall filter print', '/interface print']:
                # Check for disabled interfaces
                if 'disabled=yes' in result.stdout.lower():
                    issue = SecurityIssue(
                        severity="medium",
                        category="Configuration",
                        description="Disabled network interface detected",
                        recommendation="Review and enable necessary interfaces or remove unused ones"
                    )
                    issues.append(issue)

        return issues
    
    @staticmethod
    def analyze_network_health(router_info: RouterInfo) -> Dict[str, Any]:
        """Analyze overall network health and provide recommendations"""
        health_analysis = {
            "overall_score": 0,
            "issues": [],
            "recommendations": []
        }
        
        # Implement health analysis logic
        # This is a placeholder for actual implementation
        
        return health_analysis

    @staticmethod
    def find_text_files(output_dir: str) -> dict[str, str]:
        """Find all text files in output directory for CLI display"""
        import os
        text_files: dict[str, str] = {}

        if not os.path.exists(output_dir):
            return text_files

        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file.endswith('.txt'):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, output_dir)
                    text_files[relative_path] = file_path
        
        return text_files