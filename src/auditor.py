"""MikroTik audit business logic orchestrator."""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

from colorama import Fore, Style
from tqdm import tqdm

from src.config import (
    AuditConfig, AuditLevel, CommandResult,
    RouterInfo, SecurityIssue, redact_sensitive_data
)
from src.commands import (
    AUDIT_COMMANDS_BASIC,
    AUDIT_COMMANDS_STANDARD,
    AUDIT_COMMANDS_COMPREHENSIVE,
    AUDIT_PROFILES,
)
from src.ssh_handler import SSHHandler
from src.security_analyzer import SecurityAnalyzer
from src.data_parser import DataParser
from src.models import NetworkOverview

logger = logging.getLogger(__name__)


class MikroTikAuditor:
    """Main audit orchestrator - business logic only."""

    def __init__(self, config: AuditConfig):
        """Initialize auditor."""
        self.config = config
        self.ssh: Optional[SSHHandler] = None
        self.results: List[CommandResult] = []
        self.router_info: Optional[RouterInfo] = None
        self._security_issues: List[SecurityIssue] = []
        self._network_overview: Optional[NetworkOverview] = None
        self._data_parser: Optional[DataParser] = None

    def get_audit_commands(self) -> List[str]:
        """Get commands based on audit level and profile."""
        # If profile is specified, use it instead of audit level
        if self.config.audit_profile:
            profile = self.config.audit_profile.lower()
            if profile in AUDIT_PROFILES:
                logger.info(f"Using audit profile: {profile}")
                return AUDIT_PROFILES[profile]
            else:
                logger.warning(f"Unknown audit profile: {profile}. Using default audit level.")

        # Fall back to audit level
        if self.config.audit_level == AuditLevel.BASIC:
            return AUDIT_COMMANDS_BASIC
        elif self.config.audit_level == AuditLevel.COMPREHENSIVE:
            return AUDIT_COMMANDS_COMPREHENSIVE
        else:
            return AUDIT_COMMANDS_STANDARD

    def execute_command(self, index: int, command: str) -> CommandResult:
        """Execute single command with retry logic."""
        result = CommandResult(
            index=index,
            command=command,
            attempt=0
        )

        for attempt in range(1, self.config.router.max_retries + 1):
            result.attempt = attempt

            try:
                start_time = time.time()
                exit_status, stdout, stderr = self.ssh.execute_command(command)  # type: ignore
                duration = time.time() - start_time

                result.exit_status = exit_status
                result.stdout = stdout
                result.stderr = stderr
                result.duration = duration
                result.has_error = exit_status != 0

                if not result.has_error:
                    logger.debug(f"[{index}] {command} - Success ({duration:.2f}s)")
                    return result
                else:
                    result.error_type = "EXECUTION_ERROR"
                    result.error_message = stderr or f"Exit code: {exit_status}"

            except Exception as e:
                result.has_error = True
                result.error_type = type(e).__name__
                result.error_message = str(e)

                if attempt < self.config.router.max_retries:
                    logger.warning(
                        f"[{index}] Attempt {attempt}/{self.config.router.max_retries} "
                        f"failed: {result.error_message}. Retrying..."
                    )
                    time.sleep(2 ** attempt)
                else:
                    logger.error(
                        f"[{index}] All {self.config.router.max_retries} attempts failed"
                    )

        return result

    def _get_optimal_workers(self) -> int:
        """
        Determine optimal number of workers for I/O-bound SSH tasks.

        If max_workers is 0 (default), applies smart calculation
        based on command count and RouterOS capabilities.
        Otherwise, uses the user-configured value.

        SSH commands are network-bound (95%+ wait time), not CPU-bound.
        RouterOS typically handles 3-5 parallel SSH sessions well.
        """
        command_count = len(self.get_audit_commands())

        # If user configured a specific max_workers value (> 0), use it
        if self.config.max_workers > 0:
            return max(1, self.config.max_workers)

        # Smart calculation for default behavior (max_workers=0)
        # Base workers for I/O-bound tasks (network latency)
        base_workers = 4

        if command_count < 10:
            return min(3, command_count)
        elif command_count < 50:
            return min(5, base_workers)
        else:
            # Cap at 6 for large audits to avoid overwhelming the router
            return min(6, base_workers + 1)

    def _group_commands_by_priority(self, commands: List[str]) -> dict:
        """Group commands by priorities."""
        fast_commands_set = {
            '/system identity print',
            '/system resource print',
            '/system clock print',
            '/interface print stats',
        }
        heavy_commands_set = {
            '/tool sniffer quick',
            '/ip firewall filter print detail',
            '/ip firewall nat print detail',
        }
        dependent_commands_set = {
            '/export hide-sensitive',
        }

        # Use sets for O(1) lookup instead of O(n) with lists
        fast = [c for c in commands if any(f in c for f in fast_commands_set)]
        heavy = [c for c in commands if any(h in c for h in heavy_commands_set)]
        dependent = [c for c in commands if any(d in c for d in dependent_commands_set)]
        already_grouped = set(fast + heavy + dependent)
        normal = [c for c in commands if c not in already_grouped]

        return {
            'fast': fast,
            'heavy': heavy,
            'dependent': dependent,
            'normal': normal
        }

    def _execute_command_group(self, commands: List[str], max_workers: int, start_idx: int, total: int, phase_desc: str = ""):
        """Execute a group of commands.

        Args:
            commands: List of commands to execute
            max_workers: Maximum number of worker threads
            start_idx: Starting index for command numbering
            total: Total number of commands
            phase_desc: Description of the phase for progress bar
        """
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.execute_command, start_idx + i, cmd): (start_idx + i, cmd)
                for i, cmd in enumerate(commands)
            }

            # Use tqdm for progress bar if enabled
            if self.config.show_progress_bar:
                desc = f"{phase_desc}" if phase_desc else "Executing commands"
                with tqdm(total=len(futures), desc=desc, unit="cmd", leave=False) as pbar:
                    for future in as_completed(futures):
                        index, cmd = futures[future]
                        try:
                            result = future.result()
                            self.results.append(result)
                            status = "[OK]" if not result.has_error else "[FAIL]"
                            pbar.set_postfix_str(f"{status} {cmd[:40]}{'...' if len(cmd) > 40 else ''}")
                            pbar.update(1)
                        except Exception as e:
                            pbar.set_postfix_str(f"[FAIL] {cmd[:40]}{'...' if len(cmd) > 40 else ''} (Error: {str(e)[:20]})")
                            pbar.update(1)
            else:
                # Verbose logging mode
                for future in as_completed(futures):
                    index, cmd = futures[future]
                    try:
                        result = future.result()
                        self.results.append(result)
                        status = f"{Fore.GREEN}[OK]{Style.RESET_ALL}" if not result.has_error else f"{Fore.RED}[FAIL]{Style.RESET_ALL}"
                        logger.info(
                            f"[{Fore.CYAN}{index}{Style.RESET_ALL}/{Fore.CYAN}{total}{Style.RESET_ALL}] {status} {Fore.YELLOW}{cmd[:50]}{Style.RESET_ALL}"
                            f"{'...' if len(cmd) > 50 else ''} ({result.duration:.2f}s)"
                        )
                    except Exception as e:
                        logger.error(f"[{index}] Failed: {e}")

    def run_audit(self) -> bool:
        """Run complete audit."""
        try:
            # Connect to router
            self.ssh = SSHHandler(self.config.router)
            self.ssh.connect()

            # Get router info
            logger.info("Collecting router information...")
            version_info = self.ssh.get_version_info()
            self.router_info = RouterInfo(
                identity=version_info.get("identity", "Unknown"),
                model=version_info.get("model", "MikroTik Router"),
                version=version_info.get("version", "Unknown"),
                ip=self.config.router.router_ip,
                uptime=version_info.get("uptime"),
                cpu_count=version_info.get("cpu_count", 1),
                board_name=version_info.get("board_name"),
                architecture=version_info.get("architecture"),
            )

            logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            logger.info(f"{Fore.CYAN}🔧 MikroTik Router Audit{Style.RESET_ALL}")
            logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            logger.info(f"{Fore.GREEN}[+] Connected to router:{Style.RESET_ALL} {self.router_info.identity}")
            logger.info(f"{Fore.CYAN}  Model:{Style.RESET_ALL} {self.router_info.model}")
            logger.info(f"{Fore.CYAN}  Version:{Style.RESET_ALL} v{self.router_info.version}")
            logger.info(f"{Fore.CYAN}  IP:{Style.RESET_ALL} {self.router_info.ip}")
            logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

            # Get audit commands
            commands = self.get_audit_commands()
            total = len(commands)
            optimal_workers = self._get_optimal_workers()

            logger.info(f"\n{Fore.CYAN}📋 Audit Configuration:{Style.RESET_ALL}")
            logger.info(f"  Level: {Fore.YELLOW}{self.config.audit_level.value}{Style.RESET_ALL}")
            # Show user-provided vs auto-calculated
            if self.config.max_workers > 0:
                logger.info(f"  Workers: {Fore.YELLOW}{optimal_workers}{Style.RESET_ALL} (user-configured)")
            else:
                logger.info(f"  Workers: {Fore.YELLOW}{optimal_workers}{Style.RESET_ALL} (auto-detected)")
            logger.info(f"  Commands: {Fore.YELLOW}{total}{Style.RESET_ALL}")
            logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

            # Group commands by priority
            grouped = self._group_commands_by_priority(commands)

            # Execute by groups
            self._execute_phase(grouped, total)

            # Sort results by index
            self.results.sort(key=lambda x: x.index)

            # Apply redaction if enabled
            if self.config.redact_sensitive:
                logger.info("Applying sensitive data redaction...")
                for result in self.results:
                    if result.stdout:
                        result.stdout = redact_sensitive_data(result.stdout)
                    if result.stderr:
                        result.stderr = redact_sensitive_data(result.stderr)

            # Parse all data
            logger.info(f"\n{Fore.YELLOW}[+] Parsing collected data...{Style.RESET_ALL}")
            self._data_parser = DataParser()
            self._network_overview = self._data_parser.build_network_overview(self.results)
            logger.info(f"  {Fore.GREEN}[+] Parsed {self._network_overview.total_interfaces} interfaces{Style.RESET_ALL}")
            logger.info(f"  {Fore.GREEN}[+] Parsed {self._network_overview.total_ip_addresses} IP addresses{Style.RESET_ALL}")
            logger.info(f"  {Fore.GREEN}[+] Parsed {self._network_overview.dhcp_leases_count} DHCP leases{Style.RESET_ALL}")
            logger.info(f"  {Fore.GREEN}[+] Parsed {len(self._network_overview.services)} services{Style.RESET_ALL}")
            logger.info(f"  {Fore.GREEN}[+] Parsed {len(self._network_overview.certificates)} certificates{Style.RESET_ALL}")

            # Analyze security
            self._analyze_security()

            # Prepare output directory
            output_dir = Path(self.config.output_dir or f"audit-reports/{self.get_timestamp()}")

            # Return output_dir for use by caller
            self._output_dir = output_dir

            # Perform backup and generate reports (delegated to caller)
            return True

        except Exception as e:
            logger.error(f"Audit failed: {e}", exc_info=True)
            return False
        finally:
            if self.ssh:
                self.ssh.close()

    def _execute_phase(self, grouped: dict, total: int) -> None:
        """
        Execute command phases in priority order.

        Phases:
        1. Fast commands (system info, stats)
        2. Heavy commands (firewall rules, sniffer)
        3. Normal commands (all others)
        4. Dependent commands (sequential, like export)

        Args:
            grouped: Dictionary with 'fast', 'heavy', 'normal', 'dependent' command lists
            total: Total number of commands for progress tracking
        """
        # Phase 1: Fast commands
        if grouped['fast']:
            if self.config.show_progress_bar:
                logger.info(f"\n{Fore.YELLOW}> Phase 1: Fast commands ({len(grouped['fast'])})...{Style.RESET_ALL}\n")
            self._execute_command_group(grouped['fast'], self._get_optimal_workers(), 1, total, "Phase 1: Fast")

        # Phase 2: Heavy commands
        if grouped['heavy']:
            if self.config.show_progress_bar:
                logger.info(f"\n{Fore.YELLOW}> Phase 2: Heavy commands ({len(grouped['heavy'])})...{Style.RESET_ALL}\n")
            start_idx = len(grouped['fast']) + 1
            self._execute_command_group(grouped['heavy'], self._get_optimal_workers(), start_idx, total, "Phase 2: Heavy")

        # Phase 3: Normal commands
        if grouped['normal']:
            if self.config.show_progress_bar:
                logger.info(f"\n{Fore.YELLOW}> Phase 3: Normal commands ({len(grouped['normal'])})...{Style.RESET_ALL}\n")
            start_idx = len(grouped['fast']) + len(grouped['heavy']) + 1
            self._execute_command_group(grouped['normal'], self._get_optimal_workers(), start_idx, total, "Phase 3: Normal")

        # Phase 4: Dependent commands (sequential)
        if grouped['dependent']:
            if self.config.show_progress_bar:
                logger.info(f"\n{Fore.YELLOW}> Phase 4: Dependent commands ({len(grouped['dependent'])})...{Style.RESET_ALL}\n")
            start_idx = len(grouped['fast']) + len(grouped['heavy']) + len(grouped['normal']) + 1
            for cmd in grouped['dependent']:
                result = self.execute_command(start_idx, cmd)
                self.results.append(result)
                if self.config.show_progress_bar:
                    status = "OK" if not result.has_error else "FAIL"
                    logger.info(f"  {status} {cmd[:50]}{'...' if len(cmd) > 50 else ''}")
                start_idx += 1

    def _analyze_security(self) -> List[SecurityIssue]:
        """Analyze security and return issues."""
        if self.config.skip_security_check:
            self._security_issues = []
            return []

        logger.info(f"\n{Fore.YELLOW}[+] Analyzing security posture...{Style.RESET_ALL}")
        self._security_issues = SecurityAnalyzer.analyze(self.results)

        # Advanced container analysis (1.8)
        container_issues = SecurityAnalyzer.analyze_containers(self.results)
        self._security_issues.extend(container_issues)
        if container_issues:
            logger.info(f"  {Fore.RED}⚠ Found {len(container_issues)} container-related issue(s){Style.RESET_ALL}")

        # Conflict analysis (2.1)
        conflict_issues = SecurityAnalyzer.analyze_conflicts(self.results)
        self._security_issues.extend(conflict_issues)
        if conflict_issues:
            logger.info(f"  {Fore.RED}⚠ Found {len(conflict_issues)} configuration conflict(s){Style.RESET_ALL}")

        # IoC analysis (3.2)
        ioc_issues = SecurityAnalyzer.analyze_ioc(self.results)
        self._security_issues.extend(ioc_issues)
        if ioc_issues:
            logger.critical(f"  {Fore.RED}🚨 Found {len(ioc_issues)} indicator(s) of compromise!{Style.RESET_ALL}")

        if self._security_issues:
            logger.info(f"  {Fore.RED}⚠ Found {len(self._security_issues)} security issue(s){Style.RESET_ALL}")
        else:
            logger.info(f"  {Fore.GREEN}[+] No security issues found{Style.RESET_ALL}")

        # Check CVE vulnerabilities if enabled
        if self.config.enable_cve_check and self.router_info:
            logger.info(f"\n{Fore.YELLOW}🔍 Checking CVE database...{Style.RESET_ALL}")
            cve_issues = SecurityAnalyzer.check_cve(
                self.router_info.version,
                use_live_lookup=self.config.enable_live_cve_lookup
            )
            self._security_issues.extend(cve_issues)

            if cve_issues:
                logger.info(f"  {Fore.RED}⚠ Found {len(cve_issues)} CVE vulnerability/vulnerabilities{Style.RESET_ALL}")
            else:
                logger.info(f"  {Fore.GREEN}[+] No CVE vulnerabilities found{Style.RESET_ALL}")

        return self._security_issues

    def get_results(self) -> List[CommandResult]:
        """Get audit results."""
        return self.results

    def get_router_info(self) -> Optional[RouterInfo]:
        """Get router information."""
        return self.router_info

    def get_security_issues(self) -> List[SecurityIssue]:
        """Get security analysis results."""
        return self._security_issues

    def get_network_overview(self) -> Optional[NetworkOverview]:
        """Get parsed network overview with all collected data."""
        return self._network_overview

    def get_output_dir(self) -> Optional[Path]:
        """Get output directory path."""
        return getattr(self, '_output_dir', None)

    @staticmethod
    def get_timestamp() -> str:
        """Get current timestamp."""
        return time.strftime("%Y%m%d_%H%M%S")
