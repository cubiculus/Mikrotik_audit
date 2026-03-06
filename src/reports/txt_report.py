"""TXT report generator for MikroTik audit results."""

import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from src.config import CommandResult, SecurityIssue, RouterInfo, BackupResult
from src.models import NetworkOverview
from src.reports.base_report import BaseReportGenerator

logger = logging.getLogger(__name__)


class TXTReportGenerator(BaseReportGenerator):
    """Generates plain text reports with all command outputs."""

    def generate(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult] = None,
        network_overview: Optional[NetworkOverview] = None
    ) -> Path:
        """Generate TXT report."""
        logger.info("Generating TXT report...")

        try:
            lines = []
            separator = "=" * 80
            report_datetime = datetime.now().strftime('%d.%m.%Y %H:%M:%S')

            # Header
            lines.append(separator)
            lines.append("MIKROTIK AUDIT REPORT - RAW COMMAND OUTPUTS")
            lines.append(separator)
            lines.append("")
            lines.append(f"Router Name:    {router_info.identity or 'Unknown'}")
            lines.append(f"Model:          {router_info.model or 'Unknown'}")
            lines.append(f"RouterOS:       {router_info.version or 'Unknown'}")
            lines.append(f"IP Address:     {router_info.ip or 'Unknown'}")
            if router_info.uptime:
                lines.append(f"Uptime:         {router_info.uptime}")
            if router_info.board_name:
                lines.append(f"Board:          {router_info.board_name}")
            if router_info.architecture:
                lines.append(f"Architecture:   {router_info.architecture}")
            lines.append("")
            lines.append(f"Report Date:    {report_datetime}")
            lines.append(separator)
            lines.append("")

            # Summary
            total = len(results)
            failed = sum(1 for r in results if r.has_error)
            lines.append(f"Total Commands: {total}")
            lines.append(f"Successful: {total - failed}")
            lines.append(f"Failed: {failed}")
            lines.append("")
            lines.append(separator)

            # Backup section
            lines.append("")
            lines.append("SYSTEM BACKUP")
            lines.append("-" * 40)
            if backup_result:
                if backup_result.status == "success":
                    size_str = f"{backup_result.file_size} bytes ({backup_result.file_size / 1024:.2f} KB)" if backup_result.file_size else "Unknown"
                    lines.append(f"Status: {backup_result.status.upper()}")
                    lines.append(f"Timestamp: {backup_result.timestamp}")
                    lines.append(f"File: {backup_result.file_name}")
                    lines.append(f"Size: {size_str}")
                    if backup_result.local_path:
                        lines.append(f"Location: {backup_result.local_path}")
                    if backup_result.download_error:
                        lines.append(f"Download Warning: {backup_result.download_error}")
                else:
                    lines.append(f"Status: {backup_result.status.upper()}")
                    lines.append(f"Error: {backup_result.error_message or 'Unknown'}")
            else:
                lines.append("Status: Not performed")
            lines.append("")
            lines.append(separator)

            # Failed commands summary
            if failed > 0:
                lines.append("")
                lines.append("FAILED COMMANDS SUMMARY")
                lines.append("-" * 40)
                for r in results:
                    if r.has_error:
                        lines.append(f"  #{r.index}: {r.command}")
                        lines.append(f"      Error: {r.error_type or 'Unknown'}")
                        lines.append(f"      Message: {r.error_message or 'N/A'}")
                        if r.stderr:
                            clean_stderr = '\n'.join(line for line in r.stderr.split('\n') if line.strip())
                            lines.append(f"      Stderr: {clean_stderr[:200]}{'...' if len(clean_stderr) > 200 else ''}")
                        lines.append("")
                lines.append(separator)

            # All command outputs
            lines.append("")
            lines.append("COMMAND OUTPUTS")
            lines.append(separator)

            for r in sorted(results, key=lambda x: x.index):
                lines.append("")
                lines.append(f"[{r.index}] {r.command}")
                lines.append("-" * 80)

                if r.has_error:
                    lines.append(f"STATUS: FAILED")
                    lines.append(f"ERROR TYPE: {r.error_type or 'Unknown'}")
                    lines.append(f"ERROR MESSAGE: {r.error_message or 'N/A'}")
                    lines.append(f"EXIT STATUS: {r.exit_status}")
                    if r.stderr:
                        lines.append("")
                        lines.append("STDERR:")
                        clean_stderr = '\n'.join(line for line in r.stderr.split('\n') if line.strip())
                        lines.append(clean_stderr)
                else:
                    lines.append(f"STATUS: SUCCESS")
                    lines.append(f"DURATION: {r.duration:.2f}s")

                lines.append("")
                lines.append("OUTPUT:")
                if r.stdout:
                    lines.append(r.stdout)
                else:
                    lines.append("(no output)")

                lines.append("")
                lines.append(separator)

            # Write report
            report_path = self.output_dir / self._get_report_filename(router_info, "txt")
            self._write_file(report_path, "\n".join(lines))
            logger.info(f"TXT report saved: {report_path}")

            return report_path

        except Exception as e:
            logger.error(f"Error generating TXT report: {e}", exc_info=True)
            raise IOError(f"Failed to generate TXT report: {e}")
