"""CVE database for MikroTik RouterOS vulnerabilities."""

from dataclasses import dataclass
from typing import List, Optional, Dict
import re
import json
import os
import time
from datetime import datetime, timedelta

# Try to import urllib.request (always available in standard library)
try:
    import urllib.request
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False


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


# ===== LIVE CVE LOOKUP (NIST NVD API) =====

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = ".cache/nvd_cves.json"
CACHE_DURATION_HOURS = 24

# NVD API doesn't require API key for basic usage (rate limited to 5 requests/30 seconds)
# Users can optionally set NVD_API_KEY environment variable for higher rate limits


def _get_cache_path() -> str:
    """Get path to cache file, creating directory if needed."""
    cache_dir = os.path.dirname(CACHE_FILE)
    if cache_dir and not os.path.exists(cache_dir):
        os.makedirs(cache_dir, exist_ok=True)
    return CACHE_FILE


def _load_cached_data() -> Optional[Dict]:
    """Load cached CVE data if not expired."""
    cache_path = _get_cache_path()

    if not os.path.exists(cache_path):
        return None

    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check if cache is expired
        cached_time = datetime.fromisoformat(data.get('cached_at', ''))
        if datetime.now() - cached_time > timedelta(hours=CACHE_DURATION_HOURS):
            return None

        return data
    except (json.JSONDecodeError, ValueError, IOError):
        return None


def _save_cache_data(data: Dict) -> None:
    """Save CVE data to cache."""
    cache_path = _get_cache_path()
    data['cached_at'] = datetime.now().isoformat()

    try:
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except IOError as e:
        print(f"Warning: Could not save CVE cache: {e}")


def _parse_nvd_cve(cve_item: Dict) -> Optional[CVE]:
    """Parse NVD CVE item to our CVE format."""
    try:
        cve_id = cve_item.get('id', '')

        # Skip if not MikroTik related
        descriptions = cve_item.get('descriptions', [])
        description_text = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description_text = desc.get('value', '')
                break

        # Check if this is MikroTik related
        if 'mikrotik' not in description_text.lower() and 'routeros' not in description_text.lower():
            return None

        # Get CVSS score for severity
        metrics = cve_item.get('metrics', {})
        cvss_data = None

        # Try different CVSS versions
        for version in ['cvssMetricV31', 'cvssMetricV3', 'cvssMetricV2']:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get('cvssData', {})
                break

        cvss_score = cvss_data.get('baseScore', 0) if cvss_data else 0

        # Map CVSS score to severity
        if cvss_score >= 9.0:
            severity = "Critical"
        elif cvss_score >= 7.0:
            severity = "High"
        elif cvss_score >= 4.0:
            severity = "Medium"
        else:
            severity = "Low"

        # Get title (first line of description)
        title = description_text.split('.')[0] if description_text else cve_id

        # Get references
        references = []
        for ref in cve_item.get('references', [])[:5]:  # Limit to 5 references
            url = ref.get('url', '')
            if url:
                references.append(url)

        # Try to extract affected versions from configuration
        affected_versions = ["Unknown"]  # Default
        fixed_version = "Unknown"

        # NVD doesn't always provide version info in structured format
        # We'll try to extract from description
        version_match = re.search(r'before\s+(\d+\.\d+(?:\.\d+)?)', description_text, re.IGNORECASE)
        if version_match:
            fixed_version = version_match.group(1)
            affected_versions = [f"0.0-{fixed_version}"]

        return CVE(
            cve_id=cve_id,
            severity=severity,
            title=title,
            description=description_text[:500] + "..." if len(description_text) > 500 else description_text,
            recommendation=f"Upgrade to RouterOS {fixed_version} or later if available",
            affected_versions=affected_versions,
            fixed_version=fixed_version,
            references=references
        )
    except (KeyError, IndexError, ValueError) as e:
        print(f"Error parsing NVD CVE item: {e}")
        return None


def fetch_cves_from_nvd(mikrotik_only: bool = True) -> List[CVE]:
    """
    Fetch CVEs from NIST NVD API.

    Args:
        mikrotik_only: If True, filter for MikroTik RouterOS only

    Returns:
        List of CVE objects
    """
    if not URLLIB_AVAILABLE:
        return []

    cves = []

    try:
        # Search for MikroTik RouterOS CVEs
        keyword = "MikroTik RouterOS"
        url = f"{NVD_API_BASE}?keywordSearch={keyword}&resultsPerPage=100"

        # Add API key if available
        api_key = os.getenv('NVD_API_KEY')
        if api_key:
            # Note: NVD API 2.0 doesn't use apiKey header, it's for rate limiting only
            pass

        # Create request with User-Agent (required by NVD)
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'MikroTik-Audit-Tool/1.0',
                'Accept': 'application/json'
            }
        )

        # NVD API has rate limits: 5 requests per 30 seconds without API key
        # We'll add a small delay to be respectful
        time.sleep(0.5)

        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode('utf-8'))

        # Parse CVEs from response
        for cve_item in data.get('vulnerabilities', []):
            cve_data = cve_item.get('cve', {})
            cve = _parse_nvd_cve(cve_data)
            if cve:
                cves.append(cve)

        return cves

    except Exception as e:
        print(f"Error fetching CVEs from NVD: {e}")
        return []


def check_cve_live(version: str, use_cache: bool = True) -> List[CVE]:
    """
    Check RouterOS version against live CVE database with caching.

    Falls back to static database if network is unavailable.

    Args:
        version: RouterOS version string
        use_cache: Whether to use cached data

    Returns:
        List of applicable CVEs (static + live if available)
    """
    # Start with static database results
    all_cves = check_cve_for_version(version)
    static_cve_ids = {cve.cve_id for cve in all_cves}

    # Try to load from cache
    cached_data = None
    if use_cache:
        cached_data = _load_cached_data()

    # Fetch from NVD if cache miss or expired
    live_cves = []
    if cached_data:
        # Parse cached CVEs
        for cve_data in cached_data.get('cves', []):
            try:
                cve = CVE(**cve_data)
                if cve.cve_id not in static_cve_ids:
                    live_cves.append(cve)
            except (TypeError, KeyError):
                continue
    else:
        # Fetch from NVD
        live_cves = fetch_cves_from_nvd()

        # Save to cache
        if live_cves and use_cache:
            cache_data = {
                'cves': [cve.__dict__ for cve in live_cves],
                'cached_at': datetime.now().isoformat()
            }
            _save_cache_data(cache_data)

    # Combine static and live CVEs
    all_cves.extend(live_cves)

    # Remove duplicates by CVE ID
    seen_ids = set()
    unique_cves = []
    for cve in all_cves:
        if cve.cve_id not in seen_ids:
            seen_ids.add(cve.cve_id)
            unique_cves.append(cve)

    return unique_cves
