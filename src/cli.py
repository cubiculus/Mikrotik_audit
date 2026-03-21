"""Command-line interface for MikroTik Audit Tool."""

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional
from datetime import datetime

import click
from colorama import Fore, Style, init
from dotenv import load_dotenv

from src.config import RouterConfig, AuditConfig, AuditLevel, BackupResult
from src.auditor import MikroTikAuditor
from src.backup_manager import BackupManager
from src.report_generator import ReportGenerator
from src.security_analyzer import SecurityAnalyzer

# Optional web interface import
try:
    from src.web.app import run_server as run_web_server
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False

# Load environment variables from .env file in project root
project_root = Path(__file__).parent.parent
load_dotenv(project_root / '.env')

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
def cli():
    """MikroTik RouterOS Audit Tool - Professional configuration auditing.

    audit: Run security audit on MikroTik RouterOS devices.
    diff: Compare two JSON audit reports to find configuration drift.

    Examples:
      python -m src.cli audit --router-ip 192.168.100.1 --audit-level Standard
      python -m src.cli diff report1.json report2.json
    """
    pass


@cli.command(name='audit')
@click.option(
    '--router-ip',
    default=None,
    help='Router IP address or hostname'
)
@click.option(
    '--ssh-port',
    default=None,
    type=int,
    help='SSH port'
)
@click.option(
    '--ssh-user',
    default=None,
    help='SSH username'
)
@click.option(
    '--ssh-key-file',
    default=None,
    type=click.Path(exists=True),
    help='Path to SSH private key file (or set MIKROTIK_SSH_KEY_FILE)'
)
@click.option(
    '--ssh-key-passphrase',
    default=None,
    hide_input=True,
    help='Passphrase for SSH key (or set MIKROTIK_SSH_KEY_PASSPHRASE)'
)
@click.option(
    '--audit-level',
    type=click.Choice(['Basic', 'Standard', 'Comprehensive']),
    default='Standard',
    help='Audit detail level'
)
@click.option(
    '--profile',
    type=click.Choice(['wifi', 'protocols', 'system', 'security', 'network', 'containers']),
    default=None,
    help='Thematic audit profile (overrides --audit-level)'
)
@click.option(
    '--output-dir',
    default=None,
    help='Output directory for reports'
)
@click.option(
    '--skip-security',
    is_flag=True,
    help='Skip security analysis'
)
@click.option(
    '--max-workers',
    default=0,
    type=int,
    help='Maximum parallel workers (0=auto-calculate)'
)
@click.option(
    '--redact',
    is_flag=True,
    help='Redact sensitive data (serial numbers, passwords, IP addresses) from reports'
)
@click.option(
    '--dry-run',
    is_flag=True,
    help='Show commands that would be executed without connecting to router'
)
@click.option(
    '--output-formats',
    default='html,json',
    help='Report formats to generate (comma-separated: html,json,txt,md)'
)
@click.option(
    '--all-formats',
    is_flag=True,
    help='Generate all report formats (html,json,txt,md). Overrides --output-formats'
)
@click.option(
    '--timeout-per-command',
    default=None,
    type=int,
    help='Timeout per command in seconds (overrides default command_timeout)'
)
@click.option(
    '--no-cve-check',
    is_flag=True,
    help='Disable CVE check for RouterOS version'
)
@click.option(
    '--no-progress-bar',
    is_flag=True,
    help='Disable progress bar and use verbose logging instead'
)
@click.option(
    '--connect-timeout',
    default=None,
    type=int,
    help='SSH connection timeout in seconds (default: 30)'
)
@click.option(
    '--command-timeout',
    default=None,
    type=int,
    help='Command execution timeout in seconds (default: 120)'
)
@click.option(
    '--no-backup',
    is_flag=True,
    help='Skip system backup (useful for read-only users)'
)
@click.option(
    '--verbose',
    is_flag=True,
    help='Enable verbose logging (DEBUG level)'
)
@click.option(
    '--quiet',
    is_flag=True,
    help='Suppress non-essential output (WARNING level only)'
)
def main(
    router_ip: Optional[str],
    ssh_port: Optional[int],
    ssh_user: Optional[str],
    ssh_key_file: Optional[str],
    ssh_key_passphrase: Optional[str],
    audit_level: str,
    profile: Optional[str],
    output_dir: Optional[str],
    skip_security: bool,
    max_workers: int,
    redact: bool,
    dry_run: bool,
    output_formats: str,
    all_formats: bool,
    timeout_per_command: Optional[int],
    no_cve_check: bool,
    no_progress_bar: bool,
    connect_timeout: Optional[int],
    command_timeout: Optional[int],
    no_backup: bool,
    verbose: bool,
    quiet: bool
):
    """MikroTik RouterOS Audit Tool - Professional configuration auditing."""

    try:
        # Configure logging level based on flags
        if verbose and quiet:
            logger.error("Cannot use both --verbose and --quiet flags")
            sys.exit(1)
        elif verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Verbose logging enabled")
        elif quiet:
            logging.getLogger().setLevel(logging.WARNING)

        # Use environment variables for values not provided via CLI
        router_ip = router_ip or os.getenv("MIKROTIK_IP", "192.168.100.1")
        ssh_port = ssh_port or int(os.getenv("MIKROTIK_PORT", "22"))
        ssh_user = ssh_user or os.getenv("MIKROTIK_USER", "admin")
        ssh_key_file = ssh_key_file or os.getenv("MIKROTIK_SSH_KEY_FILE")
        ssh_key_passphrase = ssh_key_passphrase or os.getenv("MIKROTIK_SSH_KEY_PASSPHRASE")

        # Get timeouts from CLI or environment
        connect_timeout = connect_timeout or int(os.getenv("MIKROTIK_CONNECT_TIMEOUT", "30"))
        command_timeout = command_timeout or int(os.getenv("MIKROTIK_COMMAND_TIMEOUT", "120"))

        # Handle dry-run mode early (no password or SSH connection needed)
        if dry_run:
            # For dry-run, use empty password if not provided
            ssh_pass = os.getenv("MIKROTIK_PASSWORD", "")

            config = AuditConfig(
                router=RouterConfig(
                    router_ip=router_ip,
                    ssh_port=ssh_port,
                    ssh_user=ssh_user,
                    ssh_pass=ssh_pass,
                    ssh_key_file=ssh_key_file,
                    ssh_key_passphrase=ssh_key_passphrase,
                    connect_timeout=connect_timeout,
                    command_timeout=command_timeout,
                    timeout_per_command=timeout_per_command,
                ),
                audit_level=AuditLevel(audit_level),
                audit_profile=profile,
                output_dir=output_dir,
                skip_security_check=skip_security,
                max_workers=max_workers,
                redact_sensitive=redact,
                output_formats=[f.strip().lower() for f in output_formats.split(',')],
                enable_cve_check=not no_cve_check,
                enable_live_cve_lookup=True,
                show_progress_bar=not no_progress_bar,
            )
            print_dry_run(config)
            sys.exit(0)

        # Get SSH password securely from environment or prompt (not needed for dry-run)
        ssh_pass = os.getenv("MIKROTIK_PASSWORD")  # type: ignore[assignment]
        if ssh_pass:
            logger.debug(f"Password loaded from environment variable (length: {len(ssh_pass)})")
        else:
            logger.debug("Password not found in environment variable")

        if not ssh_pass and not ssh_key_file:
            # Prompt for password securely if no SSH key provided
            ssh_pass = click.prompt(
                'SSH Password',
                hide_input=True,
                show_default=False,
                prompt_suffix=' (or set MIKROTIK_PASSWORD env var): '
            )

        # Validate that we have at least password or SSH key
        if not ssh_pass and not ssh_key_file:
            logger.error(
                "Authentication failed: No password or SSH key provided. "
                "Set MIKROTIK_PASSWORD environment variable or provide SSH key."
            )
            click.echo(
                "Error: SSH password or SSH key is required. "
                "Set MIKROTIK_PASSWORD environment variable or use --ssh-key-file.",
                err=True
            )
            sys.exit(1)

        # Create configuration
        config = AuditConfig(
            router=RouterConfig(
                router_ip=router_ip,
                ssh_port=ssh_port,
                ssh_user=ssh_user,
                ssh_pass=ssh_pass,
                ssh_key_file=ssh_key_file,
                ssh_key_passphrase=ssh_key_passphrase,
                connect_timeout=connect_timeout,
                command_timeout=command_timeout,
                timeout_per_command=timeout_per_command,
            ),
            audit_level=AuditLevel(audit_level),
            audit_profile=profile,
            output_dir=output_dir,
            skip_security_check=skip_security,
            max_workers=max_workers,
            redact_sensitive=redact,
            output_formats=[f.strip().lower() for f in output_formats.split(',')],
            enable_cve_check=not no_cve_check,
            enable_live_cve_lookup=True,
            show_progress_bar=not no_progress_bar,
        )

        # Store no_backup flag for later use
        skip_backup = no_backup

        # Handle --all-formats flag (overrides --output-formats)
        if all_formats:
            output_formats_list = ['html', 'json', 'txt', 'md']
            logger.info("Generating all report formats (--all-formats)")
        else:
            output_formats_list = [f.strip().lower() for f in output_formats.split(',')]

        # Validate output formats and warn about unknown formats
        SUPPORTED_FORMATS = {'html', 'json', 'txt', 'md'}
        unknown_formats = set(output_formats_list) - SUPPORTED_FORMATS
        if unknown_formats:
            click.echo(click.style(
                f"Warning: Unknown output format(s): {', '.join(unknown_formats)}. "
                f"Supported formats: {', '.join(sorted(SUPPORTED_FORMATS))}",
                fg='yellow'
            ), err=True)
            # Filter out unknown formats
            output_formats_list = [f for f in output_formats_list if f in SUPPORTED_FORMATS]
            if not output_formats_list:
                click.echo(click.style(
                    "Error: No valid output formats specified. Use --output-formats html,json,txt,md",
                    fg='red'
                ), err=True)
                sys.exit(1)

        # Warn about sensitive data if not redacting (not needed for dry-run)
        if not redact and not dry_run:
            click.echo(click.style(
                "WARNING: Report will include PPP secrets, Hotspot users, and serial numbers. "
                "Use --redact to mask sensitive data.",
                fg='yellow'
            ), err=True)

        # Run audit
        auditor = MikroTikAuditor(config)
        success = auditor.run_audit()

        if not success:
            logger.error("Audit failed")
            sys.exit(1)

        # Get results
        results = auditor.get_results()
        router_info = auditor.get_router_info()

        if not router_info:
            logger.error("Router info not available")
            sys.exit(1)

        # Get security issues from auditor (analysis already done in run_audit())
        security_issues = auditor.get_security_issues()

        # Get network overview with all parsed data
        network_overview = auditor.get_network_overview()

        # Get output directory from auditor
        output_path = auditor.get_output_dir() or Path(output_dir or f"audit-reports/{auditor.get_timestamp()}")

        # Perform backup (unless --no-backup flag is set)
        if skip_backup:
            logger.info(f"\n{Fore.YELLOW}System backup skipped (--no-backup flag){Style.RESET_ALL}")
            backup_result = BackupResult(
                status="skipped",
                timestamp=time.strftime("%Y%m%d_%H%M%S"),
                file_name=None,
                error_message="Skipped by user request (--no-backup)"
            )
        else:
            logger.info(f"\n{Fore.YELLOW}Performing system backup...{Style.RESET_ALL}")
            backup_manager = BackupManager(auditor.ssh)
            backup_result = backup_manager.perform_backup(output_path)

        # Continue with reports regardless of backup status
        # Skipped backups (due to insufficient permissions or --no-backup) are not fatal

        # Generate reports (only requested formats)
        logger.info(f"\n{Fore.YELLOW}Generating reports...{Style.RESET_ALL}")
        generator = ReportGenerator(output_path)

        # Use generate_all_reports with specified formats
        generated_reports = generator.generate_all_reports(
            results=results,
            security_issues=security_issues,
            router_info=router_info,
            backup_result=backup_result,
            network_overview=network_overview,
            formats=output_formats_list
        )

        # Print summary
        print_summary(results, security_issues, output_path, generated_reports)

        sys.exit(0)

    except KeyboardInterrupt:
        logger.info("\nAudit interrupted by user.")
        click.echo("\nOperation cancelled by user.", err=True)
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


def print_dry_run(config: AuditConfig):
    """Print dry-run information showing commands that would be executed."""
    from src.commands import AUDIT_COMMANDS_BASIC, AUDIT_COMMANDS_STANDARD, AUDIT_COMMANDS_COMPREHENSIVE

    # Get commands based on audit level
    if config.audit_level == AuditLevel.BASIC:
        commands = AUDIT_COMMANDS_BASIC
    elif config.audit_level == AuditLevel.COMPREHENSIVE:
        commands = AUDIT_COMMANDS_COMPREHENSIVE
    else:
        commands = AUDIT_COMMANDS_STANDARD

    click.echo(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}DRY RUN MODE{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}The following {len(commands)} commands would be executed:{Style.RESET_ALL}\n")

    for i, cmd in enumerate(commands, 1):
        click.echo(f"  {Fore.CYAN}{i:3d}.{Style.RESET_ALL} {Fore.WHITE}{cmd}{Style.RESET_ALL}")

    click.echo(f"\n{Fore.CYAN}Configuration:{Style.RESET_ALL}")
    click.echo(f"  Router:      {Fore.YELLOW}{config.router.router_ip}:{config.router.ssh_port}{Style.RESET_ALL}")
    click.echo(f"  User:        {Fore.YELLOW}{config.router.ssh_user}{Style.RESET_ALL}")
    click.echo(f"  Audit Level: {Fore.YELLOW}{config.audit_level.value}{Style.RESET_ALL}")
    click.echo(f"  Max Workers: {Fore.YELLOW}{config.max_workers if config.max_workers > 0 else 'auto'}{Style.RESET_ALL}")
    click.echo(f"  Redact:      {Fore.YELLOW}{'Yes' if config.redact_sensitive else 'No'}{Style.RESET_ALL}")
    click.echo(f"  Security:    {Fore.YELLOW}{'Skipped' if config.skip_security_check else 'Enabled'}{Style.RESET_ALL}")
    click.echo(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{Fore.GREEN}Ready to execute. Remove --dry-run to run the audit.{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


def print_summary(
    results: list,
    security_issues: list,
    output_dir: Path,
    generated_reports: dict
):
    """Print audit summary with colored security score."""
    total = len(results)
    failed = sum(1 for r in results if r.has_error)

    # Calculate security score
    security_score = SecurityAnalyzer.calculate_security_score(security_issues)
    score_color = SecurityAnalyzer.get_score_color(security_score)
    score_label = SecurityAnalyzer.get_score_label(security_score)

    logger.info(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    logger.info(f"{Fore.GREEN}Audit Complete!{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    logger.info(f"  Commands: {Fore.GREEN}{total - failed}/{total}{Style.RESET_ALL} succeeded")

    if failed > 0:
        logger.info(f"           {Fore.RED}{failed}{Style.RESET_ALL} failed")

    # Display security score with color and label
    logger.info(f"  Security: {score_color}{security_score}/100{Style.RESET_ALL} ({score_label})")
    if security_issues:
        logger.info(f"           {Fore.RED}{len(security_issues)}{Style.RESET_ALL} issue(s) found")
    else:
        logger.info(f"           {Fore.GREEN}No issues found{Style.RESET_ALL}")

    logger.info(f"  Output:   {Fore.CYAN}{output_dir}{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    if generated_reports:
        logger.info("Reports saved:")
        for format_type, path in generated_reports.items():
            logger.info(f"  {format_type.upper()}: {path}")  # Показываем полный путь


@cli.command()
@click.argument('report1', type=click.Path(exists=True))
@click.argument('report2', type=click.Path(exists=True))
@click.option(
    '--output',
    '-o',
    type=click.Path(),
    help='Output file for diff results (JSON format)'
)
def diff(report1: str, report2: str, output: Optional[str]):
    """Compare two JSON audit reports and show differences.

    Shows new/resolved security issues, interface changes, and configuration drift.
    Example: python -m src.cli diff report1.json report2.json
    """

    try:
        # Load both reports
        with open(report1, 'r', encoding='utf-8') as f:
            report1_data = json.load(f)
        with open(report2, 'r', encoding='utf-8') as f:
            report2_data = json.load(f)

        click.echo(f"\n{Fore.CYAN}Comparing audit reports:{Style.RESET_ALL}")
        click.echo(f"  {Fore.GREEN}Report 1:{Style.RESET_ALL} {report1}")
        click.echo(f"  {Fore.GREEN}Report 2:{Style.RESET_ALL} {report2}\n")

        # Extract router info
        r1_info = report1_data.get('router_info', {})
        r2_info = report2_data.get('router_info', {})

        # Compare router info
        if r1_info.get('version') != r2_info.get('version'):
            click.echo(f"{Fore.YELLOW}⚠ RouterOS version changed:{Style.RESET_ALL}")
            click.echo(f"  {r1_info.get('version', 'unknown')} → {r2_info.get('version', 'unknown')}\n")

        # Compare security issues
        r1_issues = report1_data.get('security_issues', [])
        r2_issues = report2_data.get('security_issues', [])

        # Find new issues
        new_issues = [i for i in r2_issues if i not in r1_issues]
        # Find resolved issues
        resolved_issues = [i for i in r1_issues if i not in r2_issues]

        if new_issues:
            click.echo(f"{Fore.RED}🚨 New security issues ({len(new_issues)}):{Style.RESET_ALL}")
            for issue in new_issues[:10]:  # Show first 10
                click.echo(f"  • [{issue.get('severity', 'unknown').upper()}] {issue.get('finding', issue.get('description', ''))[:80]}")
            if len(new_issues) > 10:
                click.echo(f"  ... and {len(new_issues) - 10} more")
            click.echo()

        if resolved_issues:
            click.echo(f"{Fore.GREEN}✅ Resolved security issues ({len(resolved_issues)}):{Style.RESET_ALL}")
            for issue in resolved_issues[:10]:
                click.echo(f"  • [{issue.get('severity', 'unknown').upper()}] {issue.get('finding', issue.get('description', ''))[:80]}")
            if len(resolved_issues) > 10:
                click.echo(f"  ... and {len(resolved_issues) - 10} more")
            click.echo()

        # Compare network overview
        r1_overview = report1_data.get('network_overview', {})
        r2_overview = report2_data.get('network_overview', {})

        # Compare interfaces
        r1_interfaces = r1_overview.get('interfaces', [])
        r2_interfaces = r2_overview.get('interfaces', [])
        r1_iface_names = {i.get('name') for i in r1_interfaces}
        r2_iface_names = {i.get('name') for i in r2_interfaces}

        new_ifaces = r2_iface_names - r1_iface_names
        removed_ifaces = r1_iface_names - r2_iface_names

        if new_ifaces:
            click.echo(f"{Fore.CYAN}📡 New interfaces ({len(new_ifaces)}):{Style.RESET_ALL}")
            for iface in new_ifaces:
                click.echo(f"  • {iface}")
            click.echo()

        if removed_ifaces:
            click.echo(f"{Fore.CYAN}📡 Removed interfaces ({len(removed_ifaces)}):{Style.RESET_ALL}")
            for iface in removed_ifaces:
                click.echo(f"  • {iface}")
            click.echo()

        # Compare routes
        r1_routes = r1_overview.get('routes', [])
        r2_routes = r2_overview.get('routes', [])

        if len(r1_routes) != len(r2_routes):
            click.echo(f"{Fore.CYAN}🛣️  Routes changed:{Style.RESET_ALL}")
            click.echo(f"  {len(r1_routes)} → {len(r2_routes)} routes\n")

        # Summary
        click.echo(f"{Fore.CYAN}📊 Summary:{Style.RESET_ALL}")
        click.echo(f"  Security issues: {len(r1_issues)} → {len(r2_issues)} ({len(new_issues)} new, {len(resolved_issues)} resolved)")
        click.echo(f"  Interfaces: {len(r1_interfaces)} → {len(r2_interfaces)} ({len(new_ifaces)} new, {len(removed_ifaces)} removed)")
        click.echo(f"  Routes: {len(r1_routes)} → {len(r2_routes)}")

        # Output to file if requested
        if output:
            diff_result = {
                'timestamp': datetime.now().isoformat(),
                'report1': report1,
                'report2': report2,
                'new_issues': new_issues,
                'resolved_issues': resolved_issues,
                'new_interfaces': list(new_ifaces),
                'removed_interfaces': list(removed_ifaces),
                'route_count_change': len(r2_routes) - len(r1_routes),
                'security_count_change': len(r2_issues) - len(r1_issues),
            }
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(diff_result, f, indent=2, ensure_ascii=False)
            click.echo(f"\n{Fore.GREEN}Diff saved to: {output}{Style.RESET_ALL}")

    except FileNotFoundError as e:
        click.echo(f"{Fore.RED}Error: File not found: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)
    except json.JSONDecodeError as e:
        click.echo(f"{Fore.RED}Error: Invalid JSON in report: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)


@cli.command(name='web-server')
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=5000, type=int, help='Port to listen on')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def web_server(host, port, debug):
    """Start web interface."""
    if not WEB_AVAILABLE:
        click.echo(f"{Fore.RED}Error: Web interface dependencies not installed.{Style.RESET_ALL}", err=True)
        click.echo("Install with: pip install flask flask-cors", err=True)
        sys.exit(1)

    run_web_server(host=host, port=port, debug=debug)


if __name__ == '__main__':
    cli()
