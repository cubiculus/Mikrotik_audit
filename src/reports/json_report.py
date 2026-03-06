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
                    "router": router_info.dict(),
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
                            "name": c.name,
                            "status": c.status,
                            "interface": c.interface,
                            "image": c.image,
                            "root_directory": c.root_directory,
                        }
                        for c in network_overview.containers
                    ],
                    "dns": {
                        "servers": network_overview.dns.servers,
                        "allow_remote": network_overview.dns.allow_remote,
                        "use_doh": network_overview.dns.use_doh,
                        "doh_server": network_overview.dns.doh_server,
                        "cache_size": network_overview.dns.cache_size,
                        "static_entries_count": len(network_overview.dns.static_entries),
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
                            "src_address": r.src_address,
                            "routing_mark": r.routing_mark,
                            "table": r.table,
                            "comment": r.comment,
                        }
                        for r in network_overview.routing_rules
                    ],
                    "marked_routes": [
                        {
                            "dst_address": r.dst_address,
                            "gateway": r.gateway,
                            "routing_mark": r.routing_mark,
                            "active": r.active,
                        }
                        for r in network_overview.routes if r.routing_mark
                    ],
                    "dhcp_leases": [
                        {
                            "address": getattr(l, 'address', ''),
                            "mac_address": getattr(l, 'mac_address', ''),
                            "host_name": getattr(l, 'host_name', '') or getattr(l, 'client_hostname', ''),
                            "address_lists": getattr(l, 'address_lists', ''),
                            "dynamic": getattr(l, 'dynamic', getattr(l, 'dynamic_entry', False)),
                            "comment": getattr(l, 'comment', ''),
                        }
                        for l in network_overview.dhcp_leases
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
                "results": [r.dict() for r in results],
                "security_issues": [i.dict() for i in security_issues],
            }

            # Write report
            report_path = self.output_dir / self._get_report_filename(router_info, "json")
            self._write_file(report_path, json.dumps(report_data, indent=2))
            logger.info(f"JSON report saved: {report_path}")

            return report_path

        except Exception as e:
            logger.error(f"Error generating JSON report: {e}", exc_info=True)
            raise IOError(f"Failed to generate JSON report: {e}")
