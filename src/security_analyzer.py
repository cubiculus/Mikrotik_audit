"""Security analyzer for MikroTik RouterOS."""

import re
import logging
from typing import List, Callable

from src.config import CommandResult, SecurityIssue
from src.cve_database import check_cve_for_version

logger = logging.getLogger(__name__)


def _has_no_rules(out: str) -> bool:
    """Проверяет, что вывод команды не содержит правил фаервола.

    RouterOS всегда возвращает заголовок 'Flags: ...' даже для пустых списков,
    поэтому простая проверка len() < 10 не работает.
    """
    lines = [line.strip() for line in out.strip().splitlines() if line.strip()]
    rule_lines = [line for line in lines if not line.startswith("Flags:")]
    return len(rule_lines) == 0


class SecurityAnalyzer:
    """Analyzes command results for security issues."""

    # Severity weights for scoring
    SEVERITY_WEIGHTS = {
        "High": 25,
        "Medium": 10,
        "Low": 3
    }

    # Security rules: (command_pattern, severity, category, finding, recommendation)
    SECURITY_RULES: List[dict] = [
        # ===== USER MANAGEMENT =====
        {
            "command": "/user print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*"?\s*admin\b', out, re.IGNORECASE)) and bool(re.search(r'disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "High",
                    "category": "User Management",
                    "finding": "Default admin user is active with default name",
                    "recommendation": "Rename the default admin account and set a strong password"
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*"?\s*admin\b', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "User Management",
                    "finding": "Admin account name is still 'admin'",
                    "recommendation": "Rename admin account to something less predictable"
                }
            ]
        },
        {
            "command": "/user group print",
            "checks": [
                {
                    "condition": lambda out: "full" in out.lower() and "name=full" in out.lower(),
                    "severity": "Low",
                    "category": "User Management",
                    "finding": "Full administrative group exists",
                    "recommendation": "Consider creating custom groups with limited permissions"
                }
            ]
        },

        # ===== FIREWALL =====
        {
            "command": "/ip firewall filter print",
            "checks": [
                {
                    "condition": lambda out: _has_no_rules(out),
                    "severity": "High",
                    "category": "Firewall",
                    "finding": "No firewall filter rules configured",
                    "recommendation": "Configure basic firewall rules: block input, allow established connections",
                    "fix_commands": [
                        "# Basic firewall configuration - review before applying!",
                        "# Allow established/related/untracked connections",
                        "/ip firewall filter add chain=input connection-state=established,related,untracked action=accept comment=\"Allow established\" place-before=0",
                        "# Drop invalid connections",
                        "/ip firewall filter add chain=input connection-state=invalid action=drop comment=\"Drop invalid\" place-before=0",
                        "# Block WAN input (adjust interface list as needed)",
                        "/ip firewall filter add chain=input in-interface-list=!LAN connection-state=new action=drop comment=\"Block WAN input\" place-before=0",
                        "# Forward chain rules",
                        "/ip firewall filter add chain=forward connection-state=established,related,untracked action=accept comment=\"Allow established forward\"",
                        "/ip firewall filter add chain=forward connection-state=invalid action=drop comment=\"Drop invalid forward\"",
                        "/ip firewall filter add chain=forward in-interface-list=WAN connection-nat-state=!dstnat connection-state=new action=drop comment=\"Block WAN forward\""
                    ]
                },
                {
                    "condition": lambda out: "action=accept" in out.lower() and "in-interface=ether1" in out.lower() and "chain=input" in out.lower(),
                    "severity": "High",
                    "category": "Firewall",
                    "finding": "Open accept rule on WAN interface (ether1)",
                    "recommendation": "Restrict input access to specific services and IPs only",
                    "fix_commands": [
                        "# Review and restrict this rule - find it with:",
                        "/ip firewall filter print where in-interface=ether1 chain=input action=accept",
                        "# Replace with specific rules, for example:",
                        "/ip firewall filter add chain=input in-interface=ether1 src-address=YOUR_TRUSTED_IP action=accept comment=\"Allow specific IP\""
                    ]
                },
                {
                    "condition": lambda out: "chain=input" in out.lower() and "dst-port=22" in out.lower(),
                    "severity": "Medium",
                    "category": "Firewall",
                    "finding": "SSH (port 22) is exposed on input chain",
                    "recommendation": "Limit SSH access to specific source addresses or use a non-standard port",
                    "fix_commands": [
                        "# Restrict SSH to specific IPs:",
                        "/ip firewall filter add chain=input protocol=tcp dst-port=22 src-address=YOUR_TRUSTED_IP action=accept comment=\"Allow SSH from trusted IP\"",
                        "# Or change SSH port in /ip ssh set port=2222"
                    ]
                },
                {
                    "condition": lambda out: "action=accept" in out.lower() and "chain=input" in out.lower() and "dst-port=80" in out.lower(),
                    "severity": "Low",
                    "category": "Firewall",
                    "finding": "HTTP (port 80) is exposed on input chain",
                    "recommendation": "Use HTTPS instead or restrict access to specific IPs",
                    "fix_commands": [
                        "# Disable HTTP service and use HTTPS:",
                        "/ip service disable www",
                        "/ip service enable www-ssl",
                        "# Or restrict HTTP to specific IPs:",
                        "/ip firewall filter add chain=input protocol=tcp dst-port=80 src-address=YOUR_TRUSTED_IP action=accept"
                    ]
                },
                {
                    "condition": lambda out: "action=accept" in out.lower() and "chain=input" in out.lower() and "dst-port=23" in out.lower(),
                    "severity": "High",
                    "category": "Firewall",
                    "finding": "Telnet (port 23) is exposed - use SSH instead",
                    "recommendation": "Disable Telnet and use SSH for remote access",
                    "fix_commands": [
                        "# Disable Telnet service:",
                        "/ip service disable telnet",
                        "# Remove firewall rule allowing Telnet:",
                        "/ip firewall filter remove [find where dst-port=23]"
                    ]
                }
            ]
        },

        # ===== IPv6 FIREWALL =====
        {
            "command": "/ipv6 firewall filter print",
            "checks": [
                {
                    "condition": lambda out: _has_no_rules(out),
                    "severity": "High",
                    "category": "IPv6 Firewall",
                    "finding": "No IPv6 firewall filter rules configured",
                    "recommendation": "Configure IPv6 firewall rules to block unnecessary traffic"
                },
                {
                    "condition": lambda out: "action=accept" in out.lower() and "in-interface=" in out.lower() and "chain=input" in out.lower(),
                    "severity": "High",
                    "category": "IPv6 Firewall",
                    "finding": "Open accept rule on WAN interface in IPv6 firewall",
                    "recommendation": "Restrict IPv6 input access to specific services and IPs only"
                },
                {
                    "condition": lambda out: "chain=input" in out.lower() and "dst-port=22" in out.lower(),
                    "severity": "Medium",
                    "category": "IPv6 Firewall",
                    "finding": "SSH (port 22) is exposed on IPv6 input chain",
                    "recommendation": "Limit IPv6 SSH access to specific source addresses"
                }
            ]
        },

        # ===== NAT =====
        {
            "command": "/ip firewall nat print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'src-address\s*=\s*0\.0\.0\.0/0.*action\s*=\s*masquerade', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "NAT",
                    "finding": "Broad masquerade rule for all source addresses (0.0.0.0/0)",
                    "recommendation": "Consider restricting masquerade to specific internal networks (e.g., 192.168.88.0/24)"
                },
                {
                    "condition": lambda out: "dst-port=22" in out.lower() and "action=dst-nat" in out.lower(),
                    "severity": "Medium",
                    "category": "NAT",
                    "finding": "SSH port forwarding detected (port 22)",
                    "recommendation": "Consider using a non-standard port and limit source IPs"
                },
                {
                    "condition": lambda out: "dst-port=3389" in out.lower() and "action=dst-nat" in out.lower(),
                    "severity": "Medium",
                    "category": "NAT",
                    "finding": "RDP port forwarding detected (port 3389)",
                    "recommendation": "Use VPN instead or restrict source IPs strictly"
                }
            ]
        },

        # ===== SERVICES =====
        {
            "command": "/ip service print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*telnet.*disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "High",
                    "category": "Services",
                    "finding": "Telnet service is enabled",
                    "recommendation": "Disable Telnet and use SSH instead",
                    "fix_commands": [
                        "/ip service disable telnet"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*ftp.*disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "Services",
                    "finding": "FTP service is enabled",
                    "recommendation": "Use SFTP/SCP instead of FTP",
                    "fix_commands": [
                        "/ip service disable ftp"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*www.*disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "Services",
                    "finding": "HTTP (www) service is enabled",
                    "recommendation": "Use HTTPS instead of HTTP",
                    "fix_commands": [
                        "/ip service disable www",
                        "# Enable HTTPS if not already enabled:",
                        "/ip service enable www-ssl"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*api.*disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "Services",
                    "finding": "API service is enabled",
                    "recommendation": "Restrict API access to specific IPs if needed",
                    "fix_commands": [
                        "# Restrict API to specific IPs or disable:",
                        "/ip service disable api",
                        "# Or enable API-SSL for encrypted connections:",
                        "/ip service enable api-ssl"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*api-ssl.*disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "Services",
                    "finding": "API-SSL service is enabled",
                    "recommendation": "API-SSL is more secure than API, but ensure proper access controls",
                    "fix_commands": [
                        "# Ensure API-SSL is restricted to specific IPs in /ip service set api-ssl address="
                    ]
                }
            ]
        },
        {
            "command": "/ip ssh print",
            "checks": [
                {
                    "condition": lambda out: "strong-crypto: no" in out.lower(),
                    "severity": "High",
                    "category": "SSH",
                    "finding": "SSH strong crypto is disabled",
                    "recommendation": "Enable strong-crypto to require modern encryption algorithms",
                    "fix_commands": [
                        "/ip ssh set strong-crypto=yes"
                    ]
                },
                {
                    "condition": lambda out: "allow-root-login=yes" in out.lower(),
                    "severity": "High",
                    "category": "SSH",
                    "finding": "SSH allows root login",
                    "recommendation": "Disable root login and use regular user accounts",
                    "fix_commands": [
                        "/ip ssh set allow-root-login=no"
                    ]
                },
                {
                    "condition": lambda out: "forwarding-enabled: yes" in out.lower(),
                    "severity": "Medium",
                    "category": "SSH",
                    "finding": "SSH forwarding is enabled",
                    "recommendation": "Disable SSH forwarding if not needed",
                    "fix_commands": [
                        "/ip ssh set forwarding-enabled=no"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'port\s*=\s*22\b', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "SSH",
                    "finding": "SSH is using default port 22",
                    "recommendation": "Consider using a non-standard SSH port to reduce automated attacks",
                    "fix_commands": [
                        "# Consider changing SSH port to a non-standard value (e.g., 2222)",
                        "/ip ssh set port=2222"
                    ]
                }
            ]
        },

        # ===== PPP/VPN =====
        {
            "command": "/ppp secret print",
            "checks": [
                {
                    "condition": lambda out: "profile=default" in out.lower(),
                    "severity": "Medium",
                    "category": "PPP",
                    "finding": "PPP secrets using default profile",
                    "recommendation": "Create custom PPP profiles with appropriate restrictions"
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*"?\s*admin\b', out, re.IGNORECASE)),
                    "severity": "High",
                    "category": "PPP",
                    "finding": "PPP secret with name 'admin' found",
                    "recommendation": "Use unique, non-default usernames for PPP secrets"
                }
            ]
        },
        {
            "command": "/ppp profile print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*"default"', out, re.IGNORECASE)) and "local-address=0.0.0.0" in out.lower(),
                    "severity": "Medium",
                    "category": "PPP",
                    "finding": "Default PPP profile has unrestricted local address",
                    "recommendation": "Configure specific local addresses for PPP profiles"
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*"default"', out, re.IGNORECASE)) and "remote-address=0.0.0.0" in out.lower(),
                    "severity": "Medium",
                    "category": "PPP",
                    "finding": "Default PPP profile has unrestricted remote address",
                    "recommendation": "Configure address pools for PPP clients"
                }
            ]
        },

        # ===== HOTSPOT =====
        {
            "command": "/ip hotspot user print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*"admin"', out, re.IGNORECASE)),
                    "severity": "High",
                    "category": "Hotspot",
                    "finding": "Hotspot user with name 'admin' found",
                    "recommendation": "Rename default hotspot admin account"
                }
            ]
        },

        # ===== DNS =====
        {
            "command": "/ip dns print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'servers\s*=\s*"?\d+\.\d+\.\d+\.\d+\s*"?$', out, re.MULTILINE | re.IGNORECASE)) and not bool(re.search(r'servers\s*=\s*', out, re.IGNORECASE) and "," in out),
                    "severity": "Low",
                    "category": "DNS",
                    "finding": "Single DNS server configured (no redundancy)",
                    "recommendation": "Configure multiple DNS servers for redundancy"
                },
                {
                    "condition": lambda out: "allow-remote-requests: yes" in out.lower(),
                    "severity": "Medium",
                    "category": "DNS",
                    "finding": "DNS allows remote requests",
                    "recommendation": "Disable remote DNS requests to prevent DNS amplification attacks"
                }
            ]
        },

        # ===== IPSEC =====
        {
            "command": "/ip ipsec peer print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'do-not-route\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "IPsec",
                    "finding": "IPsec peer routing is enabled",
                    "recommendation": "Verify that routing is appropriate for your IPsec configuration"
                }
            ]
        },

        # ===== WIREGUARD =====
        {
            "command": "/interface wireguard peers print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'allowed-address\s*=\s*"?0\.0\.0\.0/0"?', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "WireGuard",
                    "finding": "WireGuard peer allows all addresses (0.0.0.0/0)",
                    "recommendation": "Restrict allowed-addresses to specific subnets only"
                }
            ]
        },

        # ===== DHCP =====
        {
            "command": "/ip dhcp-server network print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'gateway\s*=\s*"?\d+\.\d+\.\d+\.\d+.*1\b"?', out, re.IGNORECASE)) and out.count("gateway") > 0,
                    "severity": "Low",
                    "category": "DHCP",
                    "finding": "DHCP gateway ends with .1 (common default)",
                    "recommendation": "This is not necessarily a security issue, but verify it matches your network design"
                }
            ]
        },

        # ===== CERTIFICATES =====
        {
            "command": "/system certificate print",
            "checks": [
                {
                    "condition": lambda out: "key-size=1024" in out.lower() or "key-size=512" in out.lower(),
                    "severity": "High",
                    "category": "Certificates",
                    "finding": "Certificate with small key size (< 2048 bits) detected",
                    "recommendation": "Use certificates with at least 2048-bit RSA keys"
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*"mikrotik"', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "Certificates",
                    "finding": "Default certificate name 'mikrotik' found",
                    "recommendation": "Rename certificates to something more descriptive"
                }
            ]
        },

        # ===== BRIDGE =====
        {
            "command": "/interface bridge print",
            "checks": [
                {
                    "condition": lambda out: "default-name=bridge" in out.lower(),
                    "severity": "Low",
                    "category": "Bridge",
                    "finding": "Default bridge name detected",
                    "recommendation": "Rename bridges to descriptive names"
                }
            ]
        },

        # ===== LOGGING =====
        {
            "command": "/system logging print",
            "checks": [
                {
                    "condition": lambda out: "action=disk" in out.lower() and "prefix" not in out.lower(),
                    "severity": "Low",
                    "category": "Logging",
                    "finding": "Disk logging enabled without size rotation configuration",
                    "recommendation": "Configure log rotation to prevent disk filling"
                }
            ]
        },

        # ===== SYSTEM =====
        {
            "command": "/system resource print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'free-memory\s*=\s*"\d+ KiB"', out, re.IGNORECASE)) and bool(re.search(r'free-memory\s*=\s*"\d{1,4} KiB"', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "System",
                    "finding": "Low free memory (< 100 MB)",
                    "recommendation": "Monitor memory usage and consider upgrading or reducing services"
                }
            ]
        },

        # ===== PACKAGES =====
        {
            "command": "/system package print",
            "checks": [
                {
                    "condition": lambda out: "downgrade" in out.lower(),
                    "severity": "Low",
                    "category": "System",
                    "finding": "Package downgrade found",
                    "recommendation": "Verify package versions and consider updating"
                }
            ]
        },
    ]

    @staticmethod
    def analyze(results: List[CommandResult]) -> List[SecurityIssue]:
        """
        Analyze command results for security issues.

        Args:
            results: List of command execution results

        Returns:
            List of security issues found
        """
        issues: List[SecurityIssue] = []
        seen_issues = set()  # Track unique issues by (finding, command_pattern)

        for result in results:
            if result.has_error:
                continue

            for rule in SecurityAnalyzer.SECURITY_RULES:
                if rule["command"] in result.command:
                    for check in rule["checks"]:
                        try:
                            condition_func: Callable[[str], bool] = check["condition"]
                            if condition_func(result.stdout):
                                # Create unique key for this issue
                                issue_key = (check["finding"], rule["command"])

                                # Skip if we've already reported this issue
                                if issue_key in seen_issues:
                                    continue

                                seen_issues.add(issue_key)

                                issue = SecurityIssue(
                                    severity=check["severity"],
                                    category=check["category"],
                                    finding=check["finding"],
                                    recommendation=check["recommendation"],
                                    command=result.command,
                                    fix_commands=check.get("fix_commands", [])
                                )
                                issues.append(issue)
                                logger.warning(
                                    f"Security issue found: {check['finding']} "
                                    f"({check['severity']})"
                                )
                        except Exception as e:
                            logger.debug(f"Check failed: {e}")

        return issues

    @staticmethod
    def check_cve(router_version: str) -> List[SecurityIssue]:
        """
        Check RouterOS version against known CVE database.

        Args:
            router_version: RouterOS version string (e.g., "6.49.6", "7.10")

        Returns:
            List of security issues for vulnerable CVEs
        """
        issues: List[SecurityIssue] = []

        if not router_version or router_version == "Unknown":
            logger.warning("Router version not available, skipping CVE check")
            return issues

        logger.info(f"Checking CVE database for RouterOS version {router_version}...")

        vulnerable_cves = check_cve_for_version(router_version)

        for cve in vulnerable_cves:
            issue = SecurityIssue(
                severity=cve.severity,
                category="CVE Vulnerability",
                finding=f"[{cve.cve_id}] {cve.title}",
                description=cve.description,
                recommendation=f"{cve.recommendation} (Fixed in {cve.fixed_version})",
                command="/system resource print"
            )
            issues.append(issue)
            logger.warning(
                f"CVE found: {cve.cve_id} - {cve.title} ({cve.severity})"
            )

        if vulnerable_cves:
            logger.warning(
                f"Found {len(vulnerable_cves)} CVE vulnerabilities for version {router_version}"
            )
        else:
            logger.info(f"No known CVE vulnerabilities found for version {router_version}")

        return issues

    @staticmethod
    def calculate_security_score(issues: List[SecurityIssue]) -> int:
        """
        Calculate security score from 0 to 100 based on found issues.

        Score calculation:
        - Start with 100 points
        - Subtract points based on issue severity:
          * High severity: -25 points
          * Medium severity: -10 points
          * Low severity: -3 points
        - Score is clamped between 0 and 100

        Args:
            issues: List of security issues

        Returns:
            Security score (0-100)
        """
        score = 100

        for issue in issues:
            deduction = SecurityAnalyzer.SEVERITY_WEIGHTS.get(issue.severity, 0)
            score -= deduction

        return max(0, min(100, score))

    @staticmethod
    def get_score_color(score: int) -> str:
        """
        Get color code for security score.

        Args:
            score: Security score (0-100)

        Returns:
            Colorama color code
        """
        from colorama import Fore

        if score >= 80:
            return Fore.GREEN
        elif score >= 60:
            return Fore.YELLOW
        else:
            return Fore.RED

    @staticmethod
    def get_score_label(score: int) -> str:
        """
        Get human-readable label for security score.

        Args:
            score: Security score (0-100)

        Returns:
            Label string
        """
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Good"
        elif score >= 70:
            return "Fair"
        elif score >= 60:
            return "Moderate"
        elif score >= 50:
            return "Poor"
        elif score >= 40:
            return "Weak"
        else:
            return "Critical"
