"""Command-line interface for MikroTik Audit Tool."""

import logging
import os
import sys
from pathlib import Path
from typing import Optional

import click
from colorama import Fore, Style, init
from dotenv import load_dotenv

from src.config import RouterConfig, AuditConfig, AuditLevel
from src.auditor import MikroTikAuditor
from src.backup_manager import BackupManager
from src.report_generator import ReportGenerator

# Load environment variables from .env file
load_dotenv()

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.command()
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
    default=5,
    type=int,
    help='Maximum parallel workers'
)
@click.option(
    '--redact',
    is_flag=True,
    help='Redact sensitive data (serial numbers, passwords, IP addresses) from reports'
)
def main(
    router_ip: Optional[str],
    ssh_port: Optional[int],
    ssh_user: Optional[str],
    ssh_key_file: Optional[str],
    ssh_key_passphrase: Optional[str],
    audit_level: str,
    output_dir: Optional[str],
    skip_security: bool,
    max_workers: int,
    redact: bool
):
    """MikroTik RouterOS Audit Tool - Professional configuration auditing."""

    try:
        # Use environment variables for values not provided via CLI
        router_ip = router_ip or os.getenv("MIKROTIK_IP", "192.168.1.1")
        ssh_port = ssh_port or int(os.getenv("MIKROTIK_PORT", "22"))
        ssh_user = ssh_user or os.getenv("MIKROTIK_USER", "admin")
        ssh_key_file = ssh_key_file or os.getenv("MIKROTIK_SSH_KEY_FILE")
        ssh_key_passphrase = ssh_key_passphrase or os.getenv("MIKROTIK_SSH_KEY_PASSPHRASE")

        # Get SSH password securely from environment or prompt
        ssh_pass = os.getenv("MIKROTIK_PASSWORD")
        if not ssh_pass and not ssh_key_file:
            # Prompt for password securely if no SSH key provided
            ssh_pass = click.prompt('SSH Password', hide_input=True)

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
            ),
            audit_level=AuditLevel(audit_level),
            output_dir=output_dir,
            skip_security_check=skip_security,
            max_workers=max_workers,
            redact_sensitive=redact,
        )

        # Warn about sensitive data if not redacting
        if not redact:
            click.echo(click.style(
                "⚠️  WARNING: Report will include PPP secrets, Hotspot users, and serial numbers. "
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

        # Get output directory from auditor
        output_path = auditor.get_output_dir() or Path(output_dir or f"audit-reports/{auditor.get_timestamp()}")

        # Perform backup
        logger.info(f"\n{Fore.YELLOW}💾 Performing system backup...{Style.RESET_ALL}")
        backup_manager = BackupManager(auditor.ssh)
        backup_result = backup_manager.perform_backup(output_path)

        # Continue with reports regardless of backup status
        # Skipped backups (due to insufficient permissions) are not fatal

        # Generate reports
        logger.info(f"\n{Fore.YELLOW}📄 Generating reports...{Style.RESET_ALL}")
        generator = ReportGenerator(output_path)

        html_report = generator.generate_html_report(results, security_issues, router_info, backup_result)
        json_report = generator.generate_json_report(results, security_issues, router_info, backup_result)
        txt_report = generator.generate_txt_report(results, security_issues, router_info, backup_result)
        md_report = generator.generate_markdown_report(results, security_issues, router_info, backup_result)

        # Print summary
        print_summary(results, security_issues, output_path, html_report, json_report, txt_report, md_report)

        sys.exit(0)

    except KeyboardInterrupt:
        logger.info("\nAudit interrupted by user.")
        click.echo("\nOperation cancelled by user.", err=True)
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


def print_summary(
    results: list,
    security_issues: list,
    output_dir: Path,
    html_report: Path,
    json_report: Path,
    txt_report: Path,
    md_report: Path
):
    """Print audit summary."""
    total = len(results)
    failed = sum(1 for r in results if r.has_error)

    logger.info(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    logger.info(f"{Fore.GREEN}✓ Audit Complete!{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    logger.info(f"  Commands: {Fore.GREEN}{total - failed}/{total}{Style.RESET_ALL} succeeded")

    if failed > 0:
        logger.info(f"           {Fore.RED}{failed}{Style.RESET_ALL} failed")

    logger.info(f"  Security: {Fore.YELLOW}{len(security_issues)}{Style.RESET_ALL} issue(s)")
    logger.info(f"  Output:   {Fore.CYAN}{output_dir}{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    logger.info(f"Reports saved:")
    logger.info(f"  HTML: {html_report.name}")
    logger.info(f"  JSON: {json_report.name}")
    logger.info(f"  TXT:  {txt_report.name}")
    logger.info(f"  MD:   {md_report.name} (for forums/GitHub)")


if __name__ == '__main__':
    main()
