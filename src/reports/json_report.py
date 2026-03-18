"""JSON report generator for MikroTik audit results."""

import json
import logging
from pathlib import Path
from typing import List, Optional

from src.config import CommandResult, SecurityIssue, RouterInfo, BackupResult
from src.models import NetworkOverview
from src.reports.base_report import BaseReportGenerator

logger = logging.getLogger(__name__)


class JSONReportGenerator(BaseReportGenerator):
    """Generates structured JSON reports for further processing."""

    def generate(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult] = None,
        network_overview: Optional[NetworkOverview] = None
    ) -> Path:
        """Generate JSON report."""
        logger.info("Generating JSON report...")

        try:
            if not network_overview:
                logger.warning("Network overview not provided, some data may be missing")
                network_overview = NetworkOverview()

            # Build report data
            report_data = {
                "metadata": {
                    "timestamp": self.timestamp,
                    "router": router_info.model_dump(),
                },
                "summary": {
                    "total_commands": len(results),
                    "failed_commands": sum(1 for r in results if r.has_error),
                    "avg_duration": sum(r.duration for r in results) / len(results) if results else 0,
                    "security_issues": len(security_issues),
                    "containers_count": len(network_overview.containers),
                    "dhcp_leases_count": len(network_overview.dhcp_leases),
                    "mangle_rules_count": len(network_overview.mangle_rules),
                },
                "network_overview": {
                    "system_identity": network_overview.system_identity,
                    "system_version": network_overview.system_version,
                    "containers": [
                        {
                            "name": c.get("name", "") if isinstance(c, dict) else c.name,
                            "status": c.get("status", "") if isinstance(c, dict) else c.status,
                            "interface": c.get("interface", "") if isinstance(c, dict) else c.interface,
                            "image": c.get("image", "") if isinstance(c, dict) else c.image,
                            "root_directory": c.get("root_directory", "") if isinstance(c, dict) else c.root_directory,
                        }
                        for c in network_overview.containers
                    ],
                    "dns": {
                        "servers": network_overview.dns.servers if network_overview.dns else [],
                        "allow_remote": network_overview.dns.allow_remote if network_overview.dns else False,
                        "use_doh": network_overview.dns.use_doh if network_overview.dns else False,
                        "doh_server": network_overview.dns.doh_server if network_overview.dns else "",
                        "cache_size": network_overview.dns.cache_size if network_overview.dns else 0,
                        "static_entries_count": len(network_overview.dns.static_entries) if network_overview.dns and network_overview.dns.static_entries else 0,
                    },
                    "mangle_rules": [
                        {
                            "chain": r.chain,
                            "action": r.action,
                            "src_address": r.src_address,
                            "dst_address": r.dst_address,
                            "src_address_list": r.src_address_list,
                            "dst_address_list": r.dst_address_list,
                            "new_routing_mark": r.new_routing_mark,
                            "comment": r.comment,
                            "disabled": r.disabled,
                        }
                        for r in network_overview.mangle_rules
                    ],
                    "routing_rules": [
                        {
                            "src_address": r.get("src-address", ""),
                            "dst_address": r.get("dst-address", ""),
                            "routing_mark": r.get("routing-mark", ""),
                            "action": r.get("action", ""),
                            "comment": r.get("comment", ""),
                            "disabled": r.get("disabled", "false") == "true",
                        }
                        for r in network_overview.routing_rules
                    ],
                    "marked_routes": [
                        {
                            "dst_address": r.dst_address,
                            "gateway": r.gateway,
                            "routing_mark": r.routing_mark,
                            "disabled": r.disabled,
                            "distance": r.distance,
                            "comment": r.comment,
                        }
                        for r in network_overview.routes if r.routing_mark
                    ],
                    "dhcp_leases": [
                        {
                            "address": getattr(lease, 'address', ''),
                            "mac_address": getattr(lease, 'mac_address', ''),
                            "host_name": getattr(lease, 'host_name', '') or getattr(lease, 'client_hostname', ''),
                            "address_lists": getattr(lease, 'address_lists', ''),
                            "dynamic": getattr(lease, 'dynamic', False),
                            "comment": getattr(lease, 'comment', ''),
                        }
                        for lease in network_overview.dhcp_leases
                    ],
                    "address_lists": {k: len(v) for k, v in network_overview.address_lists.items()},
                },
                "backup": {
                    "status": backup_result.status if backup_result else "none",
                    "timestamp": backup_result.timestamp if backup_result else None,
                    "file_name": backup_result.file_name if backup_result else None,
                    "file_size": backup_result.file_size if backup_result else None,
                    "local_path": backup_result.local_path if backup_result else None,
                    "error_message": backup_result.error_message if backup_result else None,
                    "download_error": backup_result.download_error if backup_result else None,
                },
                "results": [r.model_dump() for r in results],
                "security_issues": [i.model_dump() for i in security_issues],
            }

            # Write report
            report_path = self.output_dir / self._get_report_filename(router_info, "json")
            self._write_file(report_path, json.dumps(report_data, indent=2))
            logger.info(f"JSON report saved: {report_path}")

            return report_path

        except Exception as e:
            logger.error(f"Error generating JSON report: {e}", exc_info=True)
            raise IOError(f"Failed to generate JSON report: {e}")
