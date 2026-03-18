"""Report generator orchestrator for MikroTik audit results.

This module provides a unified interface for generating reports in multiple formats.
It delegates to specialized generators for HTML, JSON, and TXT formats.
"""

import logging
from pathlib import Path
from typing import List, Optional

from src.config import CommandResult, SecurityIssue, RouterInfo, BackupResult
from src.models import NetworkOverview
from src.data_parser import DataParser

from src.reports.html_report import HTMLReportGenerator
from src.reports.json_report import JSONReportGenerator
from src.reports.txt_report import TXTReportGenerator
from src.reports.markdown_report import MarkdownReportGenerator

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Orchestrates report generation across multiple formats with shared caching."""

    def __init__(
        self,
        output_dir: Path,
        cache_dir: Optional[Path] = None,
        template_path: Optional[Path] = None
    ):
        """Initialize report generator orchestrator.

        Args:
            output_dir: Directory for output reports
            cache_dir: Directory for caching parsed data
            template_path: Path to HTML template (optional)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = Path(output_dir).name.split('_')[-1] if '_' in Path(output_dir).name else None

        # Single DataParser instance for shared caching across all report types
        self.parser = DataParser(cache_dir=cache_dir)

        # Initialize format-specific generators
        self.html_generator = HTMLReportGenerator(
            output_dir=self.output_dir,
            template_path=template_path
        )
        self.json_generator = JSONReportGenerator(output_dir=self.output_dir)
        self.txt_generator = TXTReportGenerator(output_dir=self.output_dir)
        self.md_generator = MarkdownReportGenerator(output_dir=self.output_dir)

        # Cache network overview to avoid re-parsing
        self._network_overview: Optional[NetworkOverview] = None

    def _get_network_overview(self, results: List[CommandResult]) -> NetworkOverview:
        """Get or build network overview with caching."""
        if self._network_overview is None:
            logger.debug("Building network overview...")
            self._network_overview = self.parser.build_network_overview(results)
            logger.debug(
                f"Network overview built: {self._network_overview.total_interfaces} interfaces, "
                f"{self._network_overview.total_ip_addresses} IPs, "
                f"{len(self._network_overview.containers)} containers"
            )
        else:
            logger.debug("Using cached network overview")
        return self._network_overview

    def generate_html_report(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult] = None,
        network_overview: Optional[NetworkOverview] = None
    ) -> Path:
        """Generate HTML report.

        Args:
            results: Command execution results
            security_issues: Security issues found
            router_info: Router information
            backup_result: Backup operation result
            network_overview: Pre-parsed network overview (optional)

        Returns:
            Path to generated HTML report
        """
        logger.info("Generating HTML report...")
        if network_overview is None:
            network_overview = self._get_network_overview(results)

        return self.html_generator.generate(
            results=results,
            security_issues=security_issues,
            router_info=router_info,
            backup_result=backup_result,
            network_overview=network_overview
        )

    def generate_json_report(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult] = None,
        network_overview: Optional[NetworkOverview] = None
    ) -> Path:
        """Generate JSON report.

        Args:
            results: Command execution results
            security_issues: Security issues found
            router_info: Router information
            backup_result: Backup operation result
            network_overview: Pre-parsed network overview (optional)

        Returns:
            Path to generated JSON report
        """
        logger.info("Generating JSON report...")
        if network_overview is None:
            network_overview = self._get_network_overview(results)

        return self.json_generator.generate(
            results=results,
            security_issues=security_issues,
            router_info=router_info,
            backup_result=backup_result,
            network_overview=network_overview
        )

    def generate_txt_report(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult] = None,
        network_overview: Optional[NetworkOverview] = None
    ) -> Path:
        """Generate TXT report.

        Args:
            results: Command execution results
            security_issues: Security issues found
            router_info: Router information
            backup_result: Backup operation result
            network_overview: Pre-parsed network overview (optional)

        Returns:
            Path to generated TXT report
        """
        logger.info("Generating TXT report...")
        if network_overview is None:
            network_overview = self._get_network_overview(results)

        return self.txt_generator.generate(
            results=results,
            security_issues=security_issues,
            router_info=router_info,
            backup_result=backup_result,
            network_overview=network_overview
        )

    def generate_markdown_report(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult] = None,
        network_overview: Optional[NetworkOverview] = None
    ) -> Path:
        """Generate Markdown report.

        Args:
            results: Command execution results
            security_issues: Security issues found
            router_info: Router information
            backup_result: Backup operation result
            network_overview: Pre-parsed network overview (optional)

        Returns:
            Path to generated Markdown report
        """
        logger.info("Generating Markdown report...")
        if network_overview is None:
            network_overview = self._get_network_overview(results)

        return self.md_generator.generate(
            results=results,
            security_issues=security_issues,
            router_info=router_info,
            backup_result=backup_result,
            network_overview=network_overview
        )
