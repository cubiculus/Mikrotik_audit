"""IoC (Indicators of Compromise) analyzer for MikroTik RouterOS.

This module detects signs that a router may have been compromised by an attacker.
IoC detection is separate from configuration security issues - these are signs
that someone may already have unauthorized access.

Based on known RouterOS malware patterns:
- VPNFilter (2018) - used scheduler + fetch for persistence
- Meris botnet (2021) - used proxy and SOCKS
- Various cryptominers - used containers and scripts

Detection categories:
1. Scheduler persistence backdoors
2. Unauthorized services (SOCKS, proxy)
3. Suspicious files (.php, .exe, .sh on router)
4. Unknown users with full access
5. DNS hijacking (static records for known domains)
6. Mangle sniff rules (traffic interception)
7. ARP spoofing (duplicate MACs)
"""

import re
import logging
from typing import List, Dict
from dataclasses import dataclass, field
from enum import Enum

from src.config import CommandResult

logger = logging.getLogger(__name__)


class IoCType(Enum):
    """Types of IoC indicators."""
    SCHEDULER_FETCH_BACKDOOR = "SCHEDULER_FETCH_BACKDOOR"
    SCHEDULER_SCRIPT_RUN = "SCHEDULER_SCRIPT_RUN"
    SOCKS_PROXY_ENABLED = "SOCKS_PROXY_ENABLED"
    HTTP_PROXY_ENABLED = "HTTP_PROXY_ENABLED"
    SUSPICIOUS_FILES = "SUSPICIOUS_FILES"
    UNKNOWN_FULL_ACCESS_USER = "UNKNOWN_FULL_ACCESS_USER"
    DNS_HIJACKING = "DNS_HIJACKING"
    MANGLE_SNIFF_RULE = "MANGLE_SNIFF_RULE"
    ARP_SPOOFING = "ARP_SPOOFING"
    UNUSUAL_STARTUP_SCRIPT = "UNUSUAL_STARTUP_SCRIPT"
    CRYPTOMINER_INDICATORS = "CRYPTOMINER_INDICATORS"


@dataclass
class IoCResult:
    """Result of IoC detection."""
    ioc_type: IoCType
    severity: str  # Critical, High, Medium, Low
    title: str
    description: str
    evidence: str
    recommendation: str
    command: str = ""
    remediation_commands: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


# Known malicious domains/IPs used in RouterOS attacks
KNOWN_MALICIOUS_DOMAINS = {
    'check-host.net',  # Often used in attacks
    'ip-api.com',  # Used for C2
    'api.ipify.org',  # Used for IP exfiltration
    'pastebin.com',  # Used for payload delivery
    'raw.githubusercontent.com',  # Used for payload delivery
}

KNOWN_C2_PATTERNS = {
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}',  # IP:port patterns
    r'telegram\.org/bot',  # Telegram bot C2
    r'discord\.com/api/webhooks',  # Discord webhook C2
}

# Suspicious file extensions on RouterOS
SUSPICIOUS_EXTENSIONS = {
    '.php', '.exe', '.sh', '.py', '.pl', '.rb',  # Script/executable files
    '.elf', '.bin',  # Binary files
    '.conf', '.cfg',  # Config files (could be backdoor configs)
}

# Known cryptominer pool domains
CRYPTOMINER_POOLS = {
    'pool.minexmr.com',
    'xmr.pool.minergate.com',
    'pool.hashvault.pro',
    'supportxmr.com',
    'nanopool.org',
    'nicehash.com',
}


class IoCAnalyzer:
    """
    Analyzes RouterOS configuration for indicators of compromise.

    Usage:
        analyzer = IoCAnalyzer()
        analyzer.load_data(command_results)
        iocs = analyzer.analyze()
    """

    def __init__(self):
        self.scheduler_rules: List[Dict] = []
        self.proxy_config: Dict = {}
        self.socks_config: Dict = {}
        self.files: List[Dict] = []
        self.users: List[Dict] = []
        self.dns_static: List[Dict] = []
        self.mangle_rules: List[Dict] = []
        self.arp_table: List[Dict] = []
        self.scripts: List[Dict] = []
        self.system_history: List[Dict] = []

    def load_data(self, results: List[CommandResult]) -> None:
        """Load configuration data from command results."""
        for result in results:
            if result.has_error:
                continue

            cmd = result.command.lower()
            output = result.stdout

            if 'scheduler print' in cmd:
                self.scheduler_rules = self._parse_scheduler(output)
            elif 'ip proxy print' in cmd:
                self.proxy_config = self._parse_proxy(output)
            elif 'ip socks print' in cmd:
                self.socks_config = self._parse_socks(output)
            elif '/file print' in cmd:
                self.files = self._parse_files(output)
            elif '/user print' in cmd:
                self.users = self._parse_users(output)
            elif 'ip dns static print' in cmd:
                self.dns_static = self._parse_dns_static(output)
            elif 'firewall mangle print' in cmd:
                self.mangle_rules = self._parse_mangle(output)
            elif '/ip arp print' in cmd:
                self.arp_table = self._parse_arp(output)
            elif '/system script print' in cmd:
                self.scripts = self._parse_scripts(output)
            elif '/system history print' in cmd:
                self.system_history = self._parse_history(output)

    def _parse_scheduler(self, output: str) -> List[Dict]:
        """Parse scheduler entries."""
        entries = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            if re.match(r'^\s*\d+', line):
                if current:
                    entries.append(current)
                current = {}

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\n]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2).strip()
                current[key] = value

        if current:
            entries.append(current)

        return entries

    def _parse_proxy(self, output: str) -> Dict:
        """Parse proxy configuration."""
        config = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\n]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2).strip()
                config[key] = value

        return config

    def _parse_socks(self, output: str) -> Dict:
        """Parse SOCKS configuration."""
        config = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\n]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2).strip()
                config[key] = value

        return config

    def _parse_files(self, output: str) -> List[Dict]:
        """Parse file listing."""
        files = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            if re.match(r'^\s*\d+', line):
                if current:
                    files.append(current)
                current = {}

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\n]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2).strip()
                current[key] = value

        if current:
            files.append(current)

        return files

    def _parse_users(self, output: str) -> List[Dict]:
        """Parse user entries."""
        users = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            if re.match(r'^\s*\d+', line):
                if current:
                    users.append(current)
                current = {}

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\n]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2).strip()
                current[key] = value

        if current:
            users.append(current)

        return users

    def _parse_dns_static(self, output: str) -> List[Dict]:
        """Parse DNS static entries."""
        entries = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            if re.match(r'^\s*\d+', line):
                if current:
                    entries.append(current)
                current = {}

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\n]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2).strip()
                current[key] = value

        if current:
            entries.append(current)

        return entries

    def _parse_mangle(self, output: str) -> List[Dict]:
        """Parse mangle rules."""
        rules = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            if re.match(r'^\s*\d+', line):
                if current:
                    rules.append(current)
                current = {}

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\n]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2).strip()
                current[key] = value

        if current:
            rules.append(current)

        return rules

    def _parse_arp(self, output: str) -> List[Dict]:
        """Parse ARP table."""
        entries = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            if re.match(r'^\s*\d+', line):
                if current:
                    entries.append(current)
                current = {}

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\n]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2).strip()
                current[key] = value

        if current:
            entries.append(current)

        return entries

    def _parse_scripts(self, output: str) -> List[Dict]:
        """Parse system scripts."""
        scripts = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            if re.match(r'^\s*\d+', line):
                if current:
                    scripts.append(current)
                current = {}

            for match in re.finditer(r'(\w+(?:-\w+)*)\s*[=:]\s*["\']?([^"\'\n]+)', line):
                key = match.group(1).lower().replace('-', '_')
                value = match.group(2).strip()
                current[key] = value

        if current:
            scripts.append(current)

        return scripts

    def _parse_history(self, output: str) -> List[Dict]:
        """Parse system history."""
        history = []

        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Flags:'):
                continue

            entry = {'raw': line}
            history.append(entry)

        return history

    def analyze(self) -> List[IoCResult]:
        """Run all IoC detection checks."""
        iocs = []

        iocs.extend(self._check_scheduler_backdoor())
        iocs.extend(self._check_socks_proxy())
        iocs.extend(self._check_http_proxy())
        iocs.extend(self._check_suspicious_files())
        iocs.extend(self._check_unknown_users())
        iocs.extend(self._check_dns_hijacking())
        iocs.extend(self._check_mangle_sniff())
        iocs.extend(self._check_arp_spoofing())
        iocs.extend(self._check_cryptominer_indicators())

        return iocs

    def _check_scheduler_backdoor(self) -> List[IoCResult]:
        """
        Check for scheduler-based persistence backdoors.

        VPNFilter and other malware use scheduler to:
        - Fetch payloads from external URLs
        - Execute scripts periodically
        - Exfiltrate data
        """
        iocs = []

        for entry in self.scheduler_rules:
            on_event = entry.get('on_event', '') or entry.get('on-event', '')
            name = entry.get('name', 'unknown')

            # Check for fetch to HTTP URLs (VPNFilter pattern)
            if re.search(r'fetch\s+http://', on_event, re.IGNORECASE):
                iocs.append(IoCResult(
                    ioc_type=IoCType.SCHEDULER_FETCH_BACKDOOR,
                    severity="Critical",
                    title=f"Scheduled fetch to HTTP URL in '{name}'",
                    description=(
                        f"Scheduler task '{name}' executes fetch to HTTP URL. "
                        f"This is a common persistence mechanism used by VPNFilter and other malware. "
                        f"The task downloads and potentially executes remote payloads."
                    ),
                    evidence=f"on-event: {on_event[:200]}",
                    recommendation="Remove this scheduler task immediately and investigate further",
                    command="/system scheduler print detail",
                    remediation_commands=[
                        f"/system scheduler remove [find where name=\"{name}\"]",
                        "# Investigate what the fetch downloads",
                        "/log print where message~\"fetch\"",
                        "# Check for downloaded files",
                        "/file print"
                    ],
                    references=[
                        "https://www.cisco.com/security/multivendor/iosxe/webui-privesc.html",
                        "https://www.us-cert.gov/ncas/alerts/TA18-141A"
                    ]
                ))

            # Check for /system script run (persistence)
            if re.search(r'/system\s+script\s+run', on_event, re.IGNORECASE):
                iocs.append(IoCResult(
                    ioc_type=IoCType.SCHEDULER_SCRIPT_RUN,
                    severity="High",
                    title=f"Scheduled script execution in '{name}'",
                    description=(
                        f"Scheduler task '{name}' executes /system script run. "
                        f"While this can be legitimate, it's also used by malware for persistence."
                    ),
                    evidence=f"on-event: {on_event[:200]}",
                    recommendation="Review the script being executed",
                    command="/system scheduler print detail",
                    remediation_commands=[
                        f"/system scheduler print detail where name=\"{name}\"",
                        "# Review the script",
                        "/system script print detail"
                    ]
                ))

        return iocs

    def _check_socks_proxy(self) -> List[IoCResult]:
        """
        Check for SOCKS proxy enabled.

        SOCKS proxy is commonly used by attackers as a backdoor
        to route traffic through the compromised router.
        """
        iocs = []

        enabled = self.socks_config.get('enabled', 'no')

        if enabled.lower() in ('yes', 'true'):
            iocs.append(IoCResult(
                ioc_type=IoCType.SOCKS_PROXY_ENABLED,
                severity="Critical",
                title="SOCKS proxy is enabled",
                description=(
                    "SOCKS proxy service is enabled on the router. "
                    "This is a strong indicator of compromise as SOCKS is commonly "
                    "used by attackers to create a backdoor for traffic routing. "
                    "The Meris botnet and other malware enable SOCKS proxy."
                ),
                evidence=f"SOCKS config: {self.socks_config}",
                recommendation="Disable SOCKS proxy immediately unless you explicitly configured it",
                command="/ip socks print",
                remediation_commands=[
                    "/ip socks set enabled=no",
                    "# Review SOCKS access list",
                    "/ip socks access-list print",
                    "# Check for unknown users",
                    "/user print"
                ],
                references=[
                    "https://www.mikrotik.com/security/advisories/socks-proxy-abuse/"
                ]
            ))

        return iocs

    def _check_http_proxy(self) -> List[IoCResult]:
        """
        Check for HTTP proxy enabled.

        HTTP proxy can be used for traffic interception and is
        an indicator of compromise when not intentionally configured.
        """
        iocs = []

        enabled = self.proxy_config.get('enabled', 'no')

        if enabled.lower() in ('yes', 'true'):
            iocs.append(IoCResult(
                ioc_type=IoCType.HTTP_PROXY_ENABLED,
                severity="High",
                title="HTTP proxy is enabled",
                description=(
                    "HTTP proxy service is enabled on the router. "
                    "While this can be a legitimate feature, it's also used by "
                    "attackers for traffic interception and as a C2 channel."
                ),
                evidence=f"Proxy config: {self.proxy_config}",
                recommendation="Verify this was intentionally configured",
                command="/ip proxy print",
                remediation_commands=[
                    "/ip proxy set enabled=no",
                    "# Review proxy access list",
                    "/ip proxy access-list print"
                ]
            ))

        return iocs

    def _check_suspicious_files(self) -> List[IoCResult]:
        """
        Check for suspicious files on the router.

        RouterOS should not have .php, .exe, .sh, .py files.
        These indicate potential malware or backdoor installation.
        """
        iocs = []

        for file_entry in self.files:
            filename = file_entry.get('name', '')

            # Check for suspicious extensions
            for ext in SUSPICIOUS_EXTENSIONS:
                if filename.lower().endswith(ext):
                    iocs.append(IoCResult(
                        ioc_type=IoCType.SUSPICIOUS_FILES,
                        severity="High",
                        title=f"Suspicious file detected: {filename}",
                        description=(
                            f"File with suspicious extension '{ext}' found on router. "
                            f"RouterOS should not have {ext} files. This could be malware, "
                            f"a backdoor script, or configuration file for malicious software."
                        ),
                        evidence=f"File: {filename}",
                        recommendation="Investigate and remove the file",
                        command="/file print",
                        remediation_commands=[
                            f"/file remove \"{filename}\"",
                            "# Check file contents if possible",
                            f"/file print file=\"{filename}\""
                        ]
                    ))
                    break

        return iocs

    def _check_unknown_users(self) -> List[IoCResult]:
        """
        Check for unknown users with full access.

        Attackers often create backdoor user accounts
        with full permissions for persistent access.
        """
        iocs = []

        # Known legitimate default users
        known_users = {'admin'}

        for user in self.users:
            name = user.get('name', '')
            group = user.get('group', '')
            disabled = user.get('disabled', 'no')

            # Skip disabled users
            if disabled.lower() in ('yes', 'true'):
                continue

            # Skip known users
            if name.lower() in known_users:
                continue

            # Check for full access
            if group.lower() == 'full':
                iocs.append(IoCResult(
                    ioc_type=IoCType.UNKNOWN_FULL_ACCESS_USER,
                    severity="Critical",
                    title=f"Unknown user with full access: {name}",
                    description=(
                        f"User '{name}' has full administrative access but is not "
                        f"a known legitimate user. This could be a backdoor account "
                        f"created by an attacker for persistent access."
                    ),
                    evidence=f"User: {name}, Group: {group}",
                    recommendation="Remove this user immediately if you didn't create it",
                    command="/user print detail",
                    remediation_commands=[
                        f"/user remove [find where name=\"{name}\"]",
                        "# Review all users",
                        "/user print detail",
                        "# Check login history",
                        "/log print where message~\"login\""
                    ]
                ))

        return iocs

    def _check_dns_hijacking(self) -> List[IoCResult]:
        """
        Check for DNS hijacking via static DNS records.

        Attackers may add static DNS records to redirect
        traffic to malicious sites.
        """
        iocs = []

        for entry in self.dns_static:
            name = entry.get('name', '')
            address = entry.get('address', '')

            # Check for known malicious domains
            for malicious_domain in KNOWN_MALICIOUS_DOMAINS:
                if malicious_domain.lower() in name.lower():
                    iocs.append(IoCResult(
                        ioc_type=IoCType.DNS_HIJACKING,
                        severity="High",
                        title=f"DNS static entry for suspicious domain: {name}",
                        description=(
                            f"Static DNS record found for '{name}' which is often "
                            f"used in attacks. This could be redirecting traffic to "
                            f"malicious servers."
                        ),
                        evidence=f"DNS: {name} -> {address}",
                        recommendation="Remove this DNS entry",
                        command="/ip dns static print detail",
                        remediation_commands=[
                            f"/ip dns static remove [find where name=\"{name}\"]",
                            "# Review all static DNS entries",
                            "/ip dns static print detail"
                        ]
                    ))

        return iocs

    def _check_mangle_sniff(self) -> List[IoCResult]:
        """
        Check for mangle rules that sniff/intercept traffic.

        Mangle rules can be used to intercept and modify
        traffic passing through the router.
        """
        iocs = []

        for rule in self.mangle_rules:
            action = rule.get('action', '')

            # Check for packet sniffing actions
            if action in ('sniff', 'tarpit'):
                chain = rule.get('chain', 'unknown')
                iocs.append(IoCResult(
                    ioc_type=IoCType.MANGLE_SNIFF_RULE,
                    severity="High",
                    title=f"Suspicious mangle rule: {action} in {chain}",
                    description=(
                        f"Mangle rule with action '{action}' detected. "
                        f"This could be used to intercept, modify, or disrupt "
                        f"network traffic."
                    ),
                    evidence=f"Rule: {rule}",
                    recommendation="Review and remove if not legitimate",
                    command="/ip firewall mangle print detail",
                    remediation_commands=[
                        "# Review mangle rules",
                        "/ip firewall mangle print detail",
                        "# Remove suspicious rule",
                        f"/ip firewall mangle remove [find where action={action}]"
                    ]
                ))

        return iocs

    def _check_arp_spoofing(self) -> List[IoCResult]:
        """
        Check for ARP spoofing indicators.

        Duplicate MAC addresses in ARP table can indicate
        an ARP spoofing attack on the network.
        """
        iocs = []

        mac_to_ips: Dict[str, List[str]] = {}

        for entry in self.arp_table:
            mac = entry.get('mac_address', '')
            ip = entry.get('address', '')

            if mac and ip:
                if mac not in mac_to_ips:
                    mac_to_ips[mac] = []
                mac_to_ips[mac].append(ip)

        # Check for MACs with multiple IPs
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                iocs.append(IoCResult(
                    ioc_type=IoCType.ARP_SPOOFING,
                    severity="Medium",
                    title=f"Possible ARP spoofing: MAC {mac} has multiple IPs",
                    description=(
                        f"MAC address {mac} is associated with multiple IP addresses "
                        f"({', '.join(ips)}). This could indicate ARP spoofing attack "
                        f"where an attacker is impersonating multiple hosts."
                    ),
                    evidence=f"MAC: {mac}, IPs: {', '.join(ips)}",
                    recommendation="Investigate the affected hosts",
                    command="/ip arp print detail",
                    remediation_commands=[
                        "# Clear ARP cache",
                        "/ip arp flush",
                        "# Monitor for recurrence",
                        "/ip arp monitor"
                    ]
                ))

        return iocs

    def _check_cryptominer_indicators(self) -> List[IoCResult]:
        """
        Check for cryptominer indicators.

        Cryptominers often use specific patterns:
        - Connections to mining pools
        - High CPU usage scripts
        - Specific DNS entries
        """
        iocs = []

        # Check DNS static for mining pools
        for entry in self.dns_static:
            name = entry.get('name', '')
            for pool in CRYPTOMINER_POOLS:
                if pool.lower() in name.lower():
                    iocs.append(IoCResult(
                        ioc_type=IoCType.CRYPTOMINER_INDICATORS,
                        severity="High",
                        title=f"Possible cryptominer: DNS entry for {name}",
                        description=(
                            f"Static DNS record found for known mining pool '{name}'. "
                            f"This could indicate cryptominer activity on the network."
                        ),
                        evidence=f"DNS: {name}",
                        recommendation="Remove this entry and scan network for miners",
                        command="/ip dns static print detail",
                        remediation_commands=[
                            f"/ip dns static remove [find where name=\"{name}\"]",
                            "# Scan network for infected hosts",
                            "# Check for high CPU usage on devices"
                        ]
                    ))

        # Check scheduler for mining-related tasks
        for entry in self.scheduler_rules:
            on_event = entry.get('on_event', '') or entry.get('on-event', '')
            for pool in CRYPTOMINER_POOLS:
                if pool.lower() in on_event.lower():
                    iocs.append(IoCResult(
                        ioc_type=IoCType.CRYPTOMINER_INDICATORS,
                        severity="Critical",
                        title="Cryptominer scheduler task detected",
                        description=(
                            f"Scheduler task references known mining pool '{pool}'. "
                            f"This is a strong indicator of cryptominer infection."
                        ),
                        evidence=f"on-event: {on_event[:200]}",
                        recommendation="Remove scheduler task immediately",
                        command="/system scheduler print detail",
                        remediation_commands=[
                            f"/system scheduler remove [find where name=\"{entry.get('name', '')}\"]",
                            "# Scan network for infected hosts"
                        ]
                    ))

        return iocs


def analyze_ioc(results: List[CommandResult]) -> List[IoCResult]:
    """
    Convenience function to analyze IoC from command results.

    Args:
        results: List of command execution results

    Returns:
        List of IoC results found
    """
    analyzer = IoCAnalyzer()
    analyzer.load_data(results)
    return analyzer.analyze()
