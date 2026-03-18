"""Security analyzer for MikroTik RouterOS."""

import re
import logging
from typing import List, Callable
from src.config import CommandResult, SecurityIssue

logger = logging.getLogger(__name__)


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
                    "condition": lambda out: len(out.strip()) < 10 or "no items" in out.lower() or "no such item" in out.lower(),
                    "severity": "High",
                    "category": "Firewall",
                    "finding": "No firewall filter rules configured",
                    "recommendation": "Configure basic firewall rules: block input, allow established connections"
                },
                {
                    "condition": lambda out: "action=accept" in out.lower() and "in-interface=ether1" in out.lower() and "chain=input" in out.lower(),
                    "severity": "High",
                    "category": "Firewall",
                    "finding": "Open accept rule on WAN interface (ether1)",
                    "recommendation": "Restrict input access to specific services and IPs only"
                },
                {
                    "condition": lambda out: "chain=input" in out.lower() and "dst-port=22" in out.lower(),
                    "severity": "Medium",
                    "category": "Firewall",
                    "finding": "SSH (port 22) is exposed on input chain",
                    "recommendation": "Limit SSH access to specific source addresses or use a non-standard port"
                },
                {
                    "condition": lambda out: "action=accept" in out.lower() and "chain=input" in out.lower() and "dst-port=80" in out.lower(),
                    "severity": "Low",
                    "category": "Firewall",
                    "finding": "HTTP (port 80) is exposed on input chain",
                    "recommendation": "Use HTTPS instead or restrict access to specific IPs"
                },
                {
                    "condition": lambda out: "action=accept" in out.lower() and "chain=input" in out.lower() and "dst-port=23" in out.lower(),
                    "severity": "High",
                    "category": "Firewall",
                    "finding": "Telnet (port 23) is exposed - use SSH instead",
                    "recommendation": "Disable Telnet and use SSH for remote access"
                }
            ]
        },

        # ===== IPv6 FIREWALL =====
        {
            "command": "/ipv6 firewall filter print",
            "checks": [
                {
                    "condition": lambda out: len(out.strip()) < 10 or "no items" in out.lower() or "no such item" in out.lower(),
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
                    "recommendation": "Disable Telnet and use SSH instead"
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*ftp.*disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "Services",
                    "finding": "FTP service is enabled",
                    "recommendation": "Use SFTP/SCP instead of FTP"
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*www.*disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "Services",
                    "finding": "HTTP (www) service is enabled",
                    "recommendation": "Use HTTPS instead of HTTP"
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*api.*disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "Services",
                    "finding": "API service is enabled",
                    "recommendation": "Restrict API access to specific IPs if needed"
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*api-ssl.*disabled\s*=\s*no', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "Services",
                    "finding": "API-SSL service is enabled",
                    "recommendation": "API-SSL is more secure than API, but ensure proper access controls"
                }
            ]
        },
        {
            "command": "/ip ssh print",
            "checks": [
                {
                    "condition": lambda out: "strong-crypto=no" in out.lower(),
                    "severity": "High",
                    "category": "SSH",
                    "finding": "SSH strong crypto is disabled",
                    "recommendation": "Enable strong-crypto to require modern encryption algorithms"
                },
                {
                    "condition": lambda out: "allow-root-login=yes" in out.lower(),
                    "severity": "High",
                    "category": "SSH",
                    "finding": "SSH allows root login",
                    "recommendation": "Disable root login and use regular user accounts"
                },
                {
                    "condition": lambda out: "forwarding-enabled=yes" in out.lower(),
                    "severity": "Medium",
                    "category": "SSH",
                    "finding": "SSH forwarding is enabled",
                    "recommendation": "Disable SSH forwarding if not needed"
                },
                {
                    "condition": lambda out: bool(re.search(r'port\s*=\s*22\b', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "SSH",
                    "finding": "SSH is using default port 22",
                    "recommendation": "Consider using a non-standard SSH port to reduce automated attacks"
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
                    "condition": lambda out: "name=default" in out.lower() and "local-address=0.0.0.0" in out.lower(),
                    "severity": "Medium",
                    "category": "PPP",
                    "finding": "Default PPP profile has unrestricted local address",
                    "recommendation": "Configure specific local addresses for PPP profiles"
                },
                {
                    "condition": lambda out: "name=default" in out.lower() and "remote-address=0.0.0.0" in out.lower(),
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
                    "condition": lambda out: "allow-remote-requests=yes" in out.lower(),
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

        for result in results:
            if result.has_error:
                continue

            for rule in SecurityAnalyzer.SECURITY_RULES:
                if rule["command"] in result.command:
                    for check in rule["checks"]:
                        try:
                            condition_func: Callable[[str], bool] = check["condition"]
                            if condition_func(result.stdout):
                                issue = SecurityIssue(
                                    severity=check["severity"],
                                    category=check["category"],
                                    finding=check["finding"],
                                    recommendation=check["recommendation"],
                                    command=result.command
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
