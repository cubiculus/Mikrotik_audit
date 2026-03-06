"""Base report generator with shared functionality."""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from src.config import CommandResult, SecurityIssue, RouterInfo, BackupResult
from src.models import NetworkOverview

logger = logging.getLogger(__name__)


class BaseReportGenerator(ABC):
    """Abstract base class for all report generators."""

    def __init__(self, output_dir: Path):
        """Initialize base report generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    @abstractmethod
    def generate(
        self,
        results: List[CommandResult],
        security_issues: List[SecurityIssue],
        router_info: RouterInfo,
        backup_result: Optional[BackupResult] = None,
        network_overview: Optional[NetworkOverview] = None
    ) -> Path:
        """Generate report file."""
        pass

    def _get_report_filename(self, router_info: RouterInfo, extension: str) -> str:
        """Generate report filename based on router identity and timestamp."""
        # Используем identity вместо serial_number (требования безопасности)
        identity = router_info.identity or "unknown" if router_info else "unknown"
        # Заменяем недопустимые символы в имени файла
        safe_identity = "".join(c if c.isalnum() or c in '-_' else '_' for c in identity)
        return f"audit_report_{safe_identity}_{self.timestamp}.{extension}"

    def _write_file(self, file_path: Path, content: str) -> None:
        """Write content to file with UTF-8 encoding."""
        try:
            file_path.write_text(content, encoding="utf-8")
            logger.debug(f"Successfully wrote file: {file_path}")
        except Exception as e:
            logger.error(f"Error writing file {file_path}: {e}")
            raise IOError(f"Failed to write file {file_path}: {e}")

    def _get_report_statistics(self, results: List[CommandResult]) -> dict:
        """Calculate report statistics."""
        total_commands = len(results)
        failed_commands = sum(1 for r in results if r.has_error)
        success_rate = ((total_commands - failed_commands) / total_commands * 100) if total_commands > 0 else 0
        sorted_results = sorted(results, key=lambda x: x.duration, reverse=True)[:10]

        return {
            "total_commands": total_commands,
            "failed_commands": failed_commands,
            "success_rate": success_rate,
            "sorted_results": sorted_results,
        }
