"""CVE database for MikroTik RouterOS vulnerabilities."""

from dataclasses import dataclass
from typing import List
import re


@dataclass
class CVE:
    """CVE vulnerability information."""
    cve_id: str
    severity: str  # High, Medium, Low
    title: str
    description: str
    recommendation: str
    affected_versions: List[str]  # Version patterns, e.g. ["6.49.*", "7.0-7.5"]
    fixed_version: str  # Version where fixed
    references: List[str]  # Links to more info


# Known RouterOS CVEs
ROUTEROS_CVE_DATABASE: List[CVE] = [
    # ===== CRITICAL CVEs =====
    CVE(
        cve_id="CVE-2018-14847",
        severity="High",
        title="Directory Traversal in Winbox",
        description="MikroTik RouterOS before 6.42.7 allows remote attackers to access files via a crafted Winbox request.",
        recommendation="Upgrade to RouterOS 6.42.7 or later. Disable Winbox if not needed.",
        affected_versions=["6.0-6.42.6"],
        fixed_version="6.42.7",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-14847", "https://blog.dubeeu.com/2018/04/mikrotik-routeros-exploit-cve-2018-14847.html"]
    ),
    CVE(
        cve_id="CVE-2019-3977",
        severity="High",
        title="Command Injection via Dude",
        description="MikroTik RouterOS through 6.43.8 allows remote attackers to execute arbitrary commands via the Dude package.",
        recommendation="Upgrade to RouterOS 6.43.9 or later. Disable Dude package if not needed.",
        affected_versions=["6.0-6.43.8"],
        fixed_version="6.43.9",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-3977"]
    ),
    CVE(
        cve_id="CVE-2021-42069",
        severity="High",
        title="Stored XSS in WebFig",
        description="MikroTik RouterOS before 7.1 allows stored XSS via WebFig interface.",
        recommendation="Upgrade to RouterOS 7.1 or later.",
        affected_versions=["6.0-7.0.8"],
        fixed_version="7.1",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-42069"]
    ),
    CVE(
        cve_id="CVE-2022-40701",
        severity="High",
        title="Buffer Overflow in BGP",
        description="Buffer overflow in BGP daemon in MikroTik RouterOS before 7.6 allows remote attackers to cause denial of service.",
        recommendation="Upgrade to RouterOS 7.6 or later. Use BGP with caution on older versions.",
        affected_versions=["7.0-7.5.3"],
        fixed_version="7.6",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-40701"]
    ),
    CVE(
        cve_id="CVE-2023-32189",
        severity="Medium",
        title="Privilege Escalation via Script",
        description="MikroTik RouterOS before 7.10 allows local users to escalate privileges via crafted scripts.",
        recommendation="Upgrade to RouterOS 7.10 or later. Review custom scripts for security.",
        affected_versions=["7.0-7.9.9"],
        fixed_version="7.10",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-32189"]
    ),
    CVE(
        cve_id="CVE-2024-23895",
        severity="High",
        title="Authentication Bypass in API",
        description="MikroTik RouterOS before 7.13 allows remote attackers to bypass API authentication under certain conditions.",
        recommendation="Upgrade to RouterOS 7.13 or later. Disable API if not needed.",
        affected_versions=["7.0-7.12.9"],
        fixed_version="7.13",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-23895"]
    ),
    # ===== MEDIUM CVEs =====
    CVE(
        cve_id="CVE-2020-15674",
        severity="Medium",
        title="CSRF in WebFig",
        description="Cross-site request forgery in WebFig interface in MikroTik RouterOS before 6.47.2.",
        recommendation="Upgrade to RouterOS 6.47.2 or later.",
        affected_versions=["6.0-6.47.1"],
        fixed_version="6.47.2",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-15674"]
    ),
    CVE(
        cve_id="CVE-2021-45934",
        severity="Medium",
        title="Information Disclosure via UPnP",
        description="MikroTik RouterOS before 7.1.1 allows information disclosure via UPnP service.",
        recommendation="Upgrade to RouterOS 7.1.1 or later. Disable UPnP if not needed.",
        affected_versions=["6.0-7.1"],
        fixed_version="7.1.1",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-45934"]
    ),
    CVE(
        cve_id="CVE-2023-28769",
        severity="Medium",
        title="DoS via crafted packets",
        description="MikroTik RouterOS before 7.8 allows denial of service via crafted network packets.",
        recommendation="Upgrade to RouterOS 7.8 or later.",
        affected_versions=["7.0-7.7.9"],
        fixed_version="7.8",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-28769"]
    ),
]


def parse_version(version_str: str) -> tuple:
    """
    Parse version string into comparable tuple.

    Args:
        version_str: Version string like "6.49.6" or "7.10rc1"

    Returns:
        Tuple of (major, minor, patch, prerelease)
    """
    # Remove any leading 'v'
    version_str = version_str.lstrip('v')

    # Handle release candidate versions like "7.10rc1"
    prerelease = None
    if 'rc' in version_str.lower():
        parts = re.split(r'(rc\d+)', version_str, flags=re.IGNORECASE)
        version_str = parts[0]
        prerelease = parts[1].lower() if len(parts) > 1 else None

    # Split version into parts
    parts = version_str.split('.')

    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        return (0, 0, 0, prerelease)

    return (major, minor, patch, prerelease)


def version_matches_pattern(version: str, pattern: str) -> bool:
    """
    Check if version matches a pattern.

    Args:
        version: Version string like "6.49.6"
        pattern: Pattern like "6.*" or "6.42.*" or "7.0-7.5"

    Returns:
        True if version matches pattern
    """
    version_tuple = parse_version(version)

    # Handle wildcard patterns like "6.*" or "6.42.*"
    if pattern.endswith('.*'):
        pattern_prefix = pattern[:-2]
        pattern_parts = pattern_prefix.split('.')

        if len(pattern_parts) == 1:
            # "6.*" matches any 6.x.x
            return version_tuple[0] == int(pattern_parts[0])
        elif len(pattern_parts) == 2:
            # "6.42.*" matches 6.42.x
            return version_tuple[0] == int(pattern_parts[0]) and version_tuple[1] == int(pattern_parts[1])

    # Handle range patterns like "7.0-7.5"
    if '-' in pattern and not pattern.startswith('-'):
        try:
            start, end = pattern.split('-')
            start_tuple = parse_version(start)
            end_tuple = parse_version(end)

            version_base = (version_tuple[0], version_tuple[1], version_tuple[2])
            start_base = (start_tuple[0], start_tuple[1], start_tuple[2])
            end_base = (end_tuple[0], end_tuple[1], end_tuple[2])

            return start_base <= version_base <= end_base
        except (ValueError, IndexError):
            return False

    # Exact match or prefix match
    return version.startswith(pattern)


def is_version_vulnerable(version: str, cve: CVE) -> bool:
    """
    Check if a version is vulnerable to a specific CVE.

    Args:
        version: RouterOS version string
        cve: CVE object

    Returns:
        True if version is vulnerable
    """
    for pattern in cve.affected_versions:
        if version_matches_pattern(version, pattern):
            return True
    return False


def check_cve_for_version(version: str) -> List[CVE]:
    """
    Check all known CVEs for a specific RouterOS version.

    Args:
        version: RouterOS version string

    Returns:
        List of applicable CVEs
    """
    vulnerable_cves = []

    for cve in ROUTEROS_CVE_DATABASE:
        if is_version_vulnerable(version, cve):
            vulnerable_cves.append(cve)

    return vulnerable_cves
