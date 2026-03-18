"""Markdown report generator for MikroTik audit results.

Generates Markdown reports suitable for forums, GitHub, and documentation.
"""

import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from src.config import CommandResult, SecurityIssue, RouterInfo, BackupResult
from src.models import NetworkOverview
from src.reports.base_report import BaseReportGenerator

logger = logging.getLogger(__name__)


class MarkdownReportGenerator(BaseReportGenerator):
    """Generates Markdown reports for forums and GitHub."""

    def generate(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult] = None,
        network_overview: Optional[NetworkOverview] = None
    ) -> Path:
        """Generate Markdown report."""
        logger.info("Generating Markdown report...")

        try:
            # Prepare statistics
            stats = self._get_report_statistics(results)

            # Build report content
            content = self._build_markdown_report(
                results=results,
                security_issues=security_issues,
                router_info=router_info,
                backup_result=backup_result,
                network_overview=network_overview,
                stats=stats
            )

            # Write report
            report_path = self.output_dir / self._get_report_filename(router_info, "md")
            self._write_file(report_path, content)
            logger.info(f"Markdown report saved: {report_path}")

            return report_path

        except Exception as e:
            logger.error(f"Error generating Markdown report: {e}", exc_info=True)
            raise IOError(f"Failed to generate Markdown report: {e}")

    def _build_markdown_report(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult],
        network_overview: Optional[NetworkOverview],
        stats: dict
    ) -> str:
        """Build complete Markdown report content."""
        sections = []

        # Header
        sections.append(self._create_header(router_info))

        # Summary
        sections.append(self._create_summary(stats))

        # Security Issues
        if security_issues:
            sections.append(self._create_security_section(security_issues))

        # Backup Status
        if backup_result:
            sections.append(self._create_backup_section(backup_result))

        # Network Overview
        if network_overview:
            sections.append(self._create_network_overview_section(network_overview))

        # Command Results
        sections.append(self._create_commands_table(results))

        # Failed Commands
        failed = [r for r in results if r.has_error]
        if failed:
            sections.append(self._create_failed_commands_section(failed))

        # Footer
        sections.append(self._create_footer())

        return "\n\n".join(sections)

    def _create_header(self, router_info: RouterInfo) -> str:
        """Create report header."""
        return f"""# 🔍 MikroTik Audit Report

## Router Information

| Property | Value |
|----------|-------|
| **Identity** | `{router_info.identity or 'Unknown'}` |
| **Model** | `{router_info.model or 'Unknown'}` |
| **RouterOS Version** | `{router_info.version or 'Unknown'}` |
| **IP Address** | `{router_info.ip or 'Unknown'}` |
| **Uptime** | `{router_info.uptime or 'Unknown'}` |
| **CPU Count** | `{router_info.cpu_count}` |
| **Board Name** | `{router_info.board_name or 'Unknown'}` |
| **Architecture** | `{router_info.architecture or 'Unknown'}` |

**Report Generated:** {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}
"""

    def _create_summary(self, stats: dict) -> str:
        """Create audit summary."""
        total = stats["total_commands"]
        failed = stats["failed_commands"]
        success = total - failed
        rate = stats["success_rate"]

        status_emoji = "✅" if failed == 0 else "⚠️"

        return f"""## 📊 Audit Summary

{status_emoji} **Status:** {"Success" if failed == 0 else "Completed with errors"}

| Metric | Value |
|--------|-------|
| **Total Commands** | {total} |
| **Successful** | {success} |
| **Failed** | {failed} |
| **Success Rate** | {rate:.1f}% |
"""

    def _create_security_section(self, issues: List[SecurityIssue]) -> str:
        """Create security issues section."""
        lines = ["""## 🔒 Security Issues

⚠️ **Security analysis found the following issues:**
"""]

        # Group by severity
        high = [i for i in issues if i.severity == "High"]
        medium = [i for i in issues if i.severity == "Medium"]
        low = [i for i in issues if i.severity == "Low"]

        if high:
            lines.append("\n### 🔴 High Severity\n")
            for issue in high:
                lines.append(self._format_security_issue(issue))

        if medium:
            lines.append("\n### 🟡 Medium Severity\n")
            for issue in medium:
                lines.append(self._format_security_issue(issue))

        if low:
            lines.append("\n### 🔵 Low Severity\n")
            for issue in low:
                lines.append(self._format_security_issue(issue))

        return "\n".join(lines)

    def _format_security_issue(self, issue: SecurityIssue) -> str:
        """Format single security issue."""
        return f"""#### {issue.finding}

- **Category:** {issue.category}
- **Severity:** {issue.severity}
- **Recommendation:** {issue.recommendation}
- **Related Command:** `{issue.command}`
"""

    def _create_backup_section(self, backup_result: BackupResult) -> str:
        """Create backup status section."""
        if backup_result.status == "success":
            size_kb = f"{backup_result.file_size / 1024:.2f} KB" if backup_result.file_size else "Unknown"
            return f"""## 💾 Backup Status

✅ **Backup Successful**

| Property | Value |
|----------|-------|
| **Timestamp** | {backup_result.timestamp} |
| **Filename** | `{backup_result.file_name or 'N/A'}` |
| **Size** | {size_kb} |
| **Local Path** | `{backup_result.local_path or 'Not downloaded'}` |
"""
        else:
            return f"""## 💾 Backup Status

❌ **Backup Failed**

| Property | Value |
|----------|-------|
| **Timestamp** | {backup_result.timestamp} |
| **Error** | {backup_result.error_message or 'Unknown'} |
"""

    def _create_network_overview_section(self, overview: NetworkOverview) -> str:
        """Create network overview section."""
        lines = ["## 🌐 Network Overview\n"]

        # Interfaces
        if overview.interfaces:
            lines.append("### Interfaces\n")
            lines.append("| Name | Type | MAC Address | Status |")
            lines.append("|------|------|-------------|--------|")
            for iface in overview.interfaces[:20]:
                status = "🟢 Up" if getattr(iface, 'running', True) else "🔴 Down"
                mac = getattr(iface, 'mac_address', '') or '-'
                lines.append(f"| `{iface.name}` | {iface.type} | {mac} | {status} |")
            if len(overview.interfaces) > 20:
                lines.append(f"\n*...and {len(overview.interfaces) - 20} more interfaces*")
            lines.append("")

        # Containers
        if overview.containers:
            lines.append("### Containers\n")
            lines.append("| Name | Image | Status |")
            lines.append("|------|-------|--------|")
            for container in overview.containers:
                status = "🟢 Running" if container.status == "running" else "🔴 Stopped"
                lines.append(f"| `{container.name}` | {container.image or '-'} | {status} |")
            lines.append("")

        # DHCP Leases
        if overview.dhcp_leases:
            lines.append("### DHCP Leases\n")
            lines.append(f"**Total Devices:** {len(overview.dhcp_leases)}\n")
            lines.append("| IP Address | MAC Address | Hostname | Type |")
            lines.append("|------------|-------------|----------|------|")
            for lease in overview.dhcp_leases[:30]:
                lease_type = "Static" if not getattr(lease, 'dynamic', False) else "Dynamic"
                hostname = getattr(lease, 'host_name', '') or getattr(lease, 'hostname', '') or getattr(lease, 'client_hostname', '') or '-'
                lines.append(f"| {lease.address} | {lease.mac_address} | {hostname} | {lease_type} |")
            if len(overview.dhcp_leases) > 30:
                lines.append(f"\n*...and {len(overview.dhcp_leases) - 30} more devices*")
            lines.append("")

        return "\n".join(lines)

    def _create_commands_table(self, results: List[CommandResult]) -> str:
        """Create commands execution table."""
        lines = ["""## 📋 Command Execution Results

| # | Status | Command | Duration |
|---|--------|---------|----------|
"""]

        for r in results:
            status = "✅" if not r.has_error else "❌"
            cmd_short = r.command[:60] + "..." if len(r.command) > 60 else r.command
            lines.append(f"| {r.index} | {status} | `{cmd_short}` | {r.duration:.2f}s |")

        return "\n".join(lines)

    def _create_failed_commands_section(self, failed: List[CommandResult]) -> str:
        """Create detailed failed commands section."""
        lines = ["""## ❌ Failed Commands Details

"""]

        for r in failed:
            error_msg = r.error_message or "Unknown error"
            stderr_content = r.stderr or ""

            lines.append(f"""### Command #{r.index}: `{r.command}`

- **Error Type:** {r.error_type or 'N/A'}
- **Exit Status:** {r.exit_status}
- **Duration:** {r.duration:.2f}s
- **Error Message:** {error_msg}
""")

            if stderr_content:
                lines.append(f"**Stderr:**\n```bash\n{stderr_content[:500]}{'...' if len(stderr_content) > 500 else ''}\n```\n")

            lines.append("---\n")

        return "\n".join(lines)

    def _create_footer(self) -> str:
        """Create report footer."""
        return f"""---

*Report generated by MikroTik Audit Tool*
*Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
"""
