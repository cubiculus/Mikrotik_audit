"""Security analyzer for MikroTik RouterOS."""

import re
import logging
from typing import List, Callable, Optional

from src.config import CommandResult, SecurityIssue
from src.cve_database import check_cve_for_version, check_cve_live
from src.conflict_analyzer import ConflictAnalyzer
from src.ioc_analyzer import analyze_ioc

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
                },
                # ===== IP RESTRICTIONS FOR SERVICES =====
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*winbox.*disabled\s*=\s*no', out, re.IGNORECASE)) and bool(re.search(r'name\s*=\s*winbox.*address\s*=\s*""', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "Services",
                    "finding": "Winbox service is enabled without IP restriction",
                    "recommendation": "Restrict Winbox access to specific management IPs only",
                    "fix_commands": [
                        "# Restrict Winbox to specific IPs",
                        "/ip service set winbox address=YOUR_MANAGEMENT_IP/32",
                        "# Or disable Winbox entirely if not needed",
                        "/ip service disable winbox"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*ssh.*disabled\s*=\s*no', out, re.IGNORECASE)) and bool(re.search(r'name\s*=\s*ssh.*address\s*=\s*""', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "Services",
                    "finding": "SSH service is enabled without IP restriction",
                    "recommendation": "Consider restricting SSH access to specific management IPs",
                    "fix_commands": [
                        "# Restrict SSH to specific IPs",
                        "/ip service set ssh address=YOUR_MANAGEMENT_IP/32"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*api.*disabled\s*=\s*no', out, re.IGNORECASE)) and bool(re.search(r'name\s*=\s*api.*address\s*=\s*""', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "Services",
                    "finding": "API service is enabled without IP restriction",
                    "recommendation": "Restrict API access to specific management IPs only",
                    "fix_commands": [
                        "# Restrict API to specific IPs",
                        "/ip service set api address=YOUR_MANAGEMENT_IP/32",
                        "# Or disable API if not needed",
                        "/ip service disable api"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*api-ssl.*disabled\s*=\s*no', out, re.IGNORECASE)) and bool(re.search(r'name\s*=\s*api-ssl.*address\s*=\s*""', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "Services",
                    "finding": "API-SSL service is enabled without IP restriction",
                    "recommendation": "Consider restricting API-SSL access to specific management IPs",
                    "fix_commands": [
                        "# Restrict API-SSL to specific IPs",
                        "/ip service set api-ssl address=YOUR_MANAGEMENT_IP/32"
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

        # ===== ROUTERBOOT & FIRMWARE =====
        {
            "command": "/system routerboard print",
            "checks": [
                {
                    "condition": lambda out: "protected-routerboot: no" in out.lower() or "protected-routerboot: disabled" in out.lower(),
                    "severity": "Medium",
                    "category": "RouterBOOT",
                    "finding": "Protected RouterBOOT is disabled",
                    "recommendation": "Enable Protected RouterBOOT to prevent unauthorized firmware changes",
                    "fix_commands": [
                        "# Enable Protected RouterBOOT (requires physical access to re-enable if locked out)",
                        "/system routerboard settings set protected-routerboot=yes",
                        "# Warning: You have 3 seconds to press any key during boot to enter RouterBOOT",
                        "# If you forget to do this, you will need to use the reset button"
                    ]
                },
                {
                    "condition": lambda out: bool(
                        re.search(r'current-firmware:\s*\S+', out, re.IGNORECASE) and
                        re.search(r'upgrade-firmware:\s*\S+', out, re.IGNORECASE)
                    ) and not bool(
                        re.search(r'upgrade-firmware:\s*$', out, re.IGNORECASE) or
                        re.search(r'upgrade-firmware:\s*""', out, re.IGNORECASE)
                    ),
                    "severity": "Low",
                    "category": "Firmware",
                    "finding": "Firmware upgrade available (current ≠ upgrade version)",
                    "recommendation": "Consider upgrading firmware to the latest version",
                    "fix_commands": [
                        "# Check for available firmware updates",
                        "/system package update check-for-updates",
                        "# Download and install update",
                        "/system package update install",
                        "# After reboot, upgrade RouterBOOT",
                        "/system routerboard upgrade"
                    ]
                }
            ]
        },

        # ===== SNMP =====
        {
            "command": "/snmp print",
            "checks": [
                {
                    "condition": lambda out: "enabled: yes" in out.lower(),
                    "severity": "Medium",
                    "category": "SNMP",
                    "finding": "SNMP service is enabled",
                    "recommendation": "Disable SNMP if not needed, or restrict access to specific IPs",
                    "fix_commands": [
                        "# Disable SNMP if not needed",
                        "/snmp set enabled=no",
                        "# Or restrict to specific IPs",
                        "/snmp set trap-addresses=YOUR_MONITORING_SERVER_IP"
                    ]
                }
            ]
        },
        {
            "command": "/snmp community print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*"?\s*public\b', out, re.IGNORECASE)),
                    "severity": "High",
                    "category": "SNMP",
                    "finding": "SNMP community 'public' is configured",
                    "recommendation": "Remove default 'public' community and use strong community strings",
                    "fix_commands": [
                        "# Remove default public community",
                        "/snmp community remove [find where name=public]",
                        "# Create custom community with read-only access",
                        "/snmp community add name=YOUR_STRONG_COMMUNITY read-only=yes addresses=YOUR_MONITORING_SERVER_IP"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'name\s*=\s*"?\s*private\b', out, re.IGNORECASE)),
                    "severity": "High",
                    "category": "SNMP",
                    "finding": "SNMP community 'private' is configured",
                    "recommendation": "Remove default 'private' community string",
                    "fix_commands": [
                        "# Remove default private community",
                        "/snmp community remove [find where name=private]"
                    ]
                },
                {
                    "condition": lambda out: "addresses=" in out and "0.0.0.0/0" in out,
                    "severity": "Medium",
                    "category": "SNMP",
                    "finding": "SNMP community allows access from any IP (0.0.0.0/0)",
                    "recommendation": "Restrict SNMP community to specific monitoring server IPs",
                    "fix_commands": [
                        "# Restrict SNMP community to specific IPs",
                        "/snmp community set [find where name=YOUR_COMMUNITY] addresses=YOUR_MONITORING_SERVER_IP"
                    ]
                }
            ]
        },

        # ===== UPnP =====
        {
            "command": "/ip upnp print",
            "checks": [
                {
                    "condition": lambda out: "enabled: yes" in out.lower(),
                    "severity": "Medium",
                    "category": "UPnP",
                    "finding": "UPnP service is enabled",
                    "recommendation": "Disable UPnP if not needed - it can be exploited for port forwarding attacks",
                    "fix_commands": [
                        "# Disable UPnP if not needed",
                        "/ip upnp set enabled=no"
                    ]
                }
            ]
        },

        # ===== PROXY =====
        {
            "command": "/ip proxy print",
            "checks": [
                {
                    "condition": lambda out: "enabled: yes" in out.lower(),
                    "severity": "High",
                    "category": "Proxy",
                    "finding": "HTTP proxy service is enabled (potential IoC marker)",
                    "recommendation": "Disable proxy if not needed - often used by attackers for traffic interception",
                    "fix_commands": [
                        "# Disable HTTP proxy",
                        "/ip proxy set enabled=no"
                    ]
                }
            ]
        },

        # ===== RoMON =====
        {
            "command": "/tool romon print",
            "checks": [
                {
                    "condition": lambda out: "enabled: yes" in out.lower(),
                    "severity": "Low",
                    "category": "RoMON",
                    "finding": "RoMON (MikroTik Neighbor Discovery Protocol) is enabled",
                    "recommendation": "Disable RoMON if not managing devices via MAC address",
                    "fix_commands": [
                        "# Disable RoMON if not needed",
                        "/tool romon set enabled=no"
                    ]
                }
            ]
        },

        # ===== SCHEDULER =====
        {
            "command": "/system scheduler print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'on-event\s*=.*fetch\s+http://', out, re.IGNORECASE)),
                    "severity": "High",
                    "category": "Scheduler",
                    "finding": "Scheduler task executes fetch to HTTP URL (potential persistence backdoor)",
                    "recommendation": "Review scheduler tasks for unauthorized fetch commands - often used by attackers for persistence",
                    "fix_commands": [
                        "# Review all scheduler tasks",
                        "/system scheduler print detail",
                        "# Remove suspicious scheduler task",
                        "/system scheduler remove [find where on-event~\"fetch http\"]"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'on-event\s*=.*fetch\s+https://(?!check\.mikrotik\.com)', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "Scheduler",
                    "finding": "Scheduler task executes fetch to external HTTPS URL",
                    "recommendation": "Review scheduler tasks for unauthorized external connections",
                    "fix_commands": [
                        "# Review all scheduler tasks",
                        "/system scheduler print detail",
                        "# Remove suspicious scheduler task",
                        "/system scheduler remove [find where on-event~\"fetch https\"]"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'on-event\s*=.*/system\s+script\s+run', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "Scheduler",
                    "finding": "Scheduler task executes /system script run",
                    "recommendation": "Review scheduler tasks that run scripts - ensure they are legitimate",
                    "fix_commands": [
                        "# Review all scheduler tasks and scripts",
                        "/system scheduler print detail",
                        "/system script print detail"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'on-event\s*=.*:put\s+\[', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "Scheduler",
                    "finding": "Scheduler task contains :put command (potential data exfiltration)",
                    "recommendation": "Review scheduler tasks for suspicious :put commands",
                    "fix_commands": [
                        "# Review scheduler task",
                        "/system scheduler print detail where name=TASK_NAME"
                    ]
                }
            ]
        },

        # ===== CONTAINERS =====
        {
            "command": "/container print",
            "checks": [
                {
                    "condition": lambda out: "privileged=yes" in out.lower(),
                    "severity": "High",
                    "category": "Containers",
                    "finding": "Container running in privileged mode",
                    "recommendation": "Disable privileged mode unless absolutely necessary - it gives the container full access to the host",
                    "fix_commands": [
                        "# Review container privileges",
                        "/container print detail",
                        "# Recreate container without privileged mode",
                        "/container set [find name=CONTAINER_NAME] privileged=no"
                    ]
                }
            ]
        },
        {
            "command": "/container mounts print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'src\s*=\s*["\']?/flash', out, re.IGNORECASE)),
                    "severity": "Critical",
                    "category": "Containers",
                    "finding": "Container mounts /flash directory - potential host filesystem access",
                    "recommendation": "Remove /flash mount unless absolutely required - this gives container access to RouterOS filesystem",
                    "fix_commands": [
                        "# Review container mounts",
                        "/container mounts print detail",
                        "# Remove dangerous mount",
                        "/container mounts remove [find where src=/flash]"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'src\s*=\s*["\']?/rw', out, re.IGNORECASE)),
                    "severity": "Critical",
                    "category": "Containers",
                    "finding": "Container mounts /rw directory - potential host filesystem access",
                    "recommendation": "Remove /rw mount unless absolutely required - this gives container access to RouterOS read-write filesystem",
                    "fix_commands": [
                        "# Review container mounts",
                        "/container mounts print detail",
                        "# Remove dangerous mount",
                        "/container mounts remove [find where src=/rw]"
                    ]
                }
            ]
        },

        # ===== Wi-Fi / Wireless =====
        {
            "command": "/interface wifi security print",
            "checks": [
                {
                    "condition": lambda out: "wps: yes" in out.lower() or "wps-use-pbc: yes" in out.lower(),
                    "severity": "High",
                    "category": "Wi-Fi",
                    "finding": "WPS (Wi-Fi Protected Setup) is enabled",
                    "recommendation": "Disable WPS - it is vulnerable to brute-force attacks",
                    "fix_commands": [
                        "# Disable WPS on all WiFi interfaces",
                        "/interface wifi security set [find] wps=no",
                        "# Or disable WPS push-button specifically",
                        "/interface wifi security set [find] wps-use-pbc=no"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'authentication-types\s*=\s*["\']?none', out, re.IGNORECASE)),
                    "severity": "High",
                    "category": "Wi-Fi",
                    "finding": "Open WiFi network detected (no authentication)",
                    "recommendation": "Enable WPA2 or WPA3 authentication for WiFi networks",
                    "fix_commands": [
                        "# Enable WPA2 authentication",
                        "/interface wifi security set [find] authentication-types=wpa2-psk",
                        "# Set a strong passphrase",
                        "/interface wifi security set [find] passphrase=YOUR_STRONG_PASSPHRASE"
                    ]
                },
                {
                    "condition": lambda out: "wep" in out.lower() and ("authentication-types" in out.lower() or "encryption" in out.lower()),
                    "severity": "High",
                    "category": "Wi-Fi",
                    "finding": "WEP encryption detected (deprecated and insecure)",
                    "recommendation": "Upgrade to WPA2 or WPA3 - WEP can be cracked in minutes",
                    "fix_commands": [
                        "# Remove WEP encryption",
                        "/interface wifi security set [find] encryption=",
                        "# Enable WPA2 authentication",
                        "/interface wifi security set [find] authentication-types=wpa2-psk"
                    ]
                },
                {
                    "condition": lambda out: bool(re.search(r'authentication-types\s*=.*wpapsk', out, re.IGNORECASE)) and bool(re.search(r'encryption\s*=.*tkip', out, re.IGNORECASE)),
                    "severity": "Medium",
                    "category": "Wi-Fi",
                    "finding": "WPA1/TKIP encryption detected (deprecated)",
                    "recommendation": "Upgrade to WPA2/WPA3 with AES encryption - TKIP is deprecated",
                    "fix_commands": [
                        "# Disable TKIP encryption",
                        "/interface wifi security set [find] encryption=aes-ccm",
                        "# Ensure WPA2 or WPA3 is enabled",
                        "/interface wifi security set [find] authentication-types=wpa2-psk,wpa3-psk"
                    ]
                },
                {
                    "condition": lambda out: "ft: yes" in out.lower() and "wpa3" not in out.lower(),
                    "severity": "Low",
                    "category": "Wi-Fi",
                    "finding": "Fast Transition (802.11r) enabled without WPA3",
                    "recommendation": "Consider using WPA3 for better security with Fast Transition",
                    "fix_commands": [
                        "# Enable WPA3 for secure fast roaming",
                        "/interface wifi security set [find] authentication-types=wpa3-psk"
                    ]
                }
            ]
        },
        {
            "command": "/interface wifi print",
            "checks": [
                {
                    "condition": lambda out: bool(re.search(r'security\.name\s*=\s*"?\s*default', out, re.IGNORECASE)),
                    "severity": "Low",
                    "category": "Wi-Fi",
                    "finding": "WiFi interface using default security profile",
                    "recommendation": "Create custom security profiles with strong passphrases",
                    "fix_commands": [
                        "# Create custom security profile",
                        "/interface wifi security add name=custom-profile authentication-types=wpa2-psk passphrase=YOUR_STRONG_PASSPHRASE",
                        "# Apply to WiFi interface",
                        "/interface wifi set [find] security=custom-profile"
                    ]
                },
                {
                    "condition": lambda out: "hide-ssid: no" in out.lower(),
                    "severity": "Low",
                    "category": "Wi-Fi",
                    "finding": "WiFi SSID broadcast is enabled",
                    "recommendation": "Consider hiding SSID if network should not be publicly visible (not a security measure)",
                    "fix_commands": [
                        "# Hide SSID broadcast",
                        "/interface wifi set [find] hide-ssid=yes"
                    ]
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
    def check_cve(router_version: str, use_live_lookup: bool = True) -> List[SecurityIssue]:
        """
        Check RouterOS version against known CVE database.

        Uses live NIST NVD API with 24-hour caching if available,
        falls back to static database if network is unavailable.

        Args:
            router_version: RouterOS version string (e.g., "6.49.6", "7.10")
            use_live_lookup: Whether to use live NVD API lookup

        Returns:
            List of security issues for vulnerable CVEs
        """
        issues: List[SecurityIssue] = []

        if not router_version or router_version == "Unknown":
            logger.warning("Router version not available, skipping CVE check")
            return issues

        if use_live_lookup:
            logger.info(f"Checking live CVE database (NIST NVD) for RouterOS version {router_version}...")
            vulnerable_cves = check_cve_live(router_version, use_cache=True)
        else:
            logger.info(f"Checking static CVE database for RouterOS version {router_version}...")
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
    def _get_result_by_command_pattern(results: List[CommandResult], pattern: str) -> Optional[CommandResult]:
        """Get command result by pattern match."""
        for result in results:
            if pattern in result.command:
                return result
        return None

    @staticmethod
    def analyze_containers(results: List[CommandResult]) -> List[SecurityIssue]:
        """
        Advanced container security analysis.

        Analyzes:
        - Container network isolation
        - Firewall rules for container subnets
        - LAN/WAN access controls

        Args:
            results: List of command execution results

        Returns:
            List of container-related security issues
        """
        issues: List[SecurityIssue] = []

        # Get container data
        container_result = SecurityAnalyzer._get_result_by_command_pattern(results, "/container print")
        firewall_result = SecurityAnalyzer._get_result_by_command_pattern(results, "/ip firewall filter print")
        nat_result = SecurityAnalyzer._get_result_by_command_pattern(results, "/ip firewall nat print")

        if not container_result or container_result.has_error:
            return issues

        # Parse running containers with IP addresses
        containers_with_ips: list = []
        output = container_result.stdout

        # Simple parsing for container name and IP
        current_container: dict = {}
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # New container entry (starts with number or has name=)
            if re.match(r'^\s*\d+', line) or 'name=' in line:
                if current_container.get('name') and current_container.get('ip_address'):
                    containers_with_ips.append(current_container)
                current_container = {}

            # Extract name
            name_match = re.search(r'name\s*=\s*["\']?([^"\'\s]+)', line)
            if name_match:
                current_container['name'] = name_match.group(1)

            # Extract IP address
            ip_match = re.search(r'ip-address\s*=\s*["\']?([^"\'\s]+)', line)
            if ip_match:
                current_container['ip_address'] = ip_match.group(1)

            # Extract interface
            iface_match = re.search(r'interface\s*=\s*["\']?([^"\'\s]+)', line)
            if iface_match:
                current_container['interface'] = iface_match.group(1)

        # Don't forget last container
        if current_container.get('name') and current_container.get('ip_address'):
            containers_with_ips.append(current_container)

        # Check each container for firewall rules
        for container in containers_with_ips:
            container_ip = container.get('ip_address', '')
            container_name = container.get('name', '')
            container_interface = container.get('interface', '')

            if not container_ip:
                continue

            # Extract container subnet (e.g., 172.17.0.0/24 from 172.17.0.2/24)
            container_subnet = None
            if '/' in container_ip:
                container_subnet = container_ip
            else:
                # Try to determine subnet from IP
                ip_parts = container_ip.split('.')
                if len(ip_parts) == 4:
                    # Assume /24 subnet
                    container_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

            # Check if there are firewall rules for this container
            if firewall_result and not firewall_result.has_error:
                fw_output = firewall_result.stdout

                # Check for rules that explicitly allow container traffic
                has_container_rules = False
                if container_subnet:
                    # Look for rules mentioning container subnet
                    if container_subnet.replace('/24', '') in fw_output:
                        has_container_rules = True

                # Check for rules on container interface
                if container_interface and f'in-interface={container_interface}' in fw_output:
                    has_container_rules = True
                if container_interface and f'out-interface={container_interface}' in fw_output:
                    has_container_rules = True

                if not has_container_rules and container_subnet:
                    issues.append(SecurityIssue(
                        severity="High",
                        category="Containers",
                        finding=f"No firewall rules for container '{container_name}' subnet ({container_subnet})",
                        recommendation=f"Configure firewall rules to control traffic to/from container {container_name}",
                        fix_commands=[
                            "# Allow established connections from container",
                            f"/ip firewall filter add chain=forward src-address={container_subnet} connection-state=established,related action=accept comment=\"Allow established from {container_name}\"",
                            f"/ip firewall filter add chain=forward dst-address={container_subnet} connection-state=established,related action=accept comment=\"Allow established to {container_name}\"",
                            "# Block new connections from container to LAN (adjust as needed)",
                            f"/ip firewall filter add chain=forward src-address={container_subnet} dst-address=192.168.0.0/16 connection-state=new action=drop comment=\"Block {container_name} to LAN\""
                        ]
                    ))

            # Check for unrestricted internet access
            if nat_result and not nat_result.has_error:
                nat_output = nat_result.stdout

                # Check if container has masquerade rule
                has_masquerade = False
                if container_subnet and 'masquerade' in nat_output.lower():
                    # Check if masquerade applies to container subnet
                    if 'src-address=' in nat_output and container_subnet.replace('/24', '') in nat_output:
                        has_masquerade = True
                    # Or if masquerade is for all traffic going to WAN
                    if 'out-interface-list=WAN' in nat_output or 'out-interface=ether1' in nat_output:
                        has_masquerade = True

                if has_masquerade:
                    issues.append(SecurityIssue(
                        severity="Medium",
                        category="Containers",
                        finding=f"Container '{container_name}' has unrestricted internet access",
                        recommendation=f"Consider restricting internet access for container {container_name} using firewall rules",
                        fix_commands=[
                            "# Limit container internet access",
                            f"/ip firewall filter add chain=forward src-address={container_subnet} out-interface-list=WAN action=accept comment=\"Allow {container_name} to WAN\"",
                            "# Or block specific destinations",
                            f"/ip firewall filter add chain=forward src-address={container_subnet} dst-address-list=BLOCKED action=drop comment=\"Block {container_name} to blocked sites\""
                        ]
                    ))

        return issues

    @staticmethod
    def analyze_conflicts(results: List[CommandResult]) -> List[SecurityIssue]:
        """
        Analyze firewall rules for conflicts and configuration issues.

        Detects:
        - Unreachable rules (shadowed by earlier rules)
        - NAT bypassing firewall
        - Orphan routing marks
        - Interfaces not in WAN/LAN lists
        - Address list conflicts
        - Missing FastTrack rules

        Args:
            results: List of command execution results

        Returns:
            List of security issues for detected conflicts
        """
        issues: List[SecurityIssue] = []

        analyzer = ConflictAnalyzer()
        analyzer.load_data(results)
        conflicts = analyzer.analyze()

        severity_map = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low"
        }

        for conflict in conflicts:
            issue = SecurityIssue(
                severity=severity_map.get(conflict.severity, "Medium"),
                category=f"Conflict: {conflict.conflict_type.value}",
                finding=conflict.title,
                description=conflict.description,
                recommendation=conflict.recommendation,
                command=conflict.rule_command or "",
                fix_commands=conflict.fix_commands
            )
            issues.append(issue)
            logger.warning(
                f"Conflict detected: {conflict.conflict_type.value} - {conflict.title} ({conflict.severity})"
            )

        if conflicts:
            logger.warning(f"Found {len(conflicts)} configuration conflict(s)")

        return issues

    @staticmethod
    def analyze_ioc(results: List[CommandResult]) -> List[SecurityIssue]:
        """
        Analyze for Indicators of Compromise (IoC).

        Detects signs that the router may have been compromised:
        - Scheduler persistence backdoors
        - Unauthorized services (SOCKS, proxy)
        - Suspicious files
        - Unknown users with full access
        - DNS hijacking
        - Mangle sniff rules
        - ARP spoofing
        - Cryptominer indicators

        Args:
            results: List of command execution results

        Returns:
            List of security issues for detected IoC
        """
        issues: List[SecurityIssue] = []

        iocs = analyze_ioc(results)

        severity_map = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low"
        }

        for ioc in iocs:
            issue = SecurityIssue(
                severity=severity_map.get(ioc.severity, "High"),
                category=f"IoC: {ioc.ioc_type.value}",
                finding=ioc.title,
                description=ioc.description,
                recommendation=ioc.recommendation,
                command=ioc.command,
                fix_commands=ioc.remediation_commands
            )
            issues.append(issue)
            logger.critical(
                f"IoC detected: {ioc.ioc_type.value} - {ioc.title} ({ioc.severity})"
            )

        if iocs:
            logger.critical(f"Found {len(iocs)} indicator(s) of compromise!")

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
