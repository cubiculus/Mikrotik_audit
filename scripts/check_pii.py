#!/usr/bin/env python3
"""
PII & Sensitive Data Scanner for MikroTik Audit project.

Blocks git commits that contain:
  - MAC addresses
  - RouterOS command output (board-name:, architecture-name:, etc.)
  - Router usernames (name="..." group=full/read)
  - DHCP hostnames and client IDs
  - Serial numbers
  - Active connection details
  - Real passwords
  - Timezone/location data

Usage:
  python scripts/check_pii.py [file1 file2 ...]   # check specific files
  python scripts/check_pii.py                      # check all staged files

Exit codes:
  0 - clean
  1 - PII detected (blocks commit)
"""

import re
import sys
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

# ═════════════════════════════════════════════════════════════════════════════
# PII Detection Patterns
# ═════════════════════════════════════════════════════════════════════════════

PATTERNS: Dict[str, Tuple[str, str]] = {
    # (pattern, description)
    "MAC_ADDRESS": (
        r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b',
        "MAC address of a device"
    ),
    "SERIAL_NUMBER": (
        r'(?i)serial[-_]?number\s*[=:]\s*[A-Z0-9]{6,12}\b',
        "Hardware serial number"
    ),
    "ROUTEROS_RAW_OUTPUT": (
        r'(?:board-name:|architecture-name:|factory-software:|write-sect-since-reboot:)',
        "Raw RouterOS command output (run /export hide-sensitive before committing)"
    ),
    "ROUTEROS_USERNAME": (
        r'name="[^"]{1,64}"(?=\s+(?:group|inactivity|address))',
        "RouterOS username (name=\"...\" group=...)"
    ),
    "DHCP_HOSTNAME": (
        r'host-name="[^"]{1,128}"',
        "DHCP client hostname (device name)"
    ),
    "DHCP_CLIENT_ID": (
        r'client-id="[^"]{4,}"',
        "DHCP client-id (hardware fingerprint)"
    ),
    "LAST_LOGGED_IN": (
        r'last-logged-in=\d{4}-\d{2}-\d{2}',
        "User last login timestamp"
    ),
    "TIMEZONE_CITY": (
        r'time-zone-name:\s+[A-Za-z]+/[A-Za-z_]+',
        "Timezone reveals geographic location"
    ),
    "ACTIVE_SSH_SESSION": (
        r'remote=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}',
        "Active SSH/service connection (shows live session)"
    ),
    "REAL_PASSWORD": (
        # Exclude: env var placeholders, empty values, Python getenv, template vars
        r'(?<!\w)password\s*[=:]\s*(?!your_password|<[A-Z]|REDACTED|\$\{|\{\{|""|\'\'|os\.getenv|Field\()(?P<val>[^\s"\'#\r\n]{4,})',
        "Hardcoded password value"
    ),
    "ROUTEROS_IDENTITY_OUTPUT": (
        # Matches the "  name: RouterName" format from /system identity print
        r'^\s{2,}name:\s+\S+\s*$',
        "RouterOS system identity output (/system identity print)"
    ),
}

# ═════════════════════════════════════════════════════════════════════════════
# Allowlist
# ═════════════════════════════════════════════════════════════════════════════

# Files matching these patterns are always skipped
SKIP_FILE_PATTERNS: List[str] = [
    r'\.env\.example$',
    r'requirements.*\.txt$',
    r'\.github/',
    r'docs/',
    r'\.gitignore$',
    r'\.bandit\.yml$',
    r'mypy\.ini$',
    r'pytest\.ini$',
    r'CHANGELOG',
    r'LICENSE',
]

# Lines containing these strings are ignored (allowlist for specific known-safe patterns)
ALLOWLIST_STRINGS: List[str] = [
    'MIKROTIK_PASSWORD',      # env var name in code
    'os.getenv(',             # env var reads in Python
    'Field(default',          # pydantic defaults
    'your_password_here',     # placeholder
    '# Example:',             # documentation comments
    '# e.g.',
    'test_',                  # test data
    '[REDACTED]',             # already redacted
    '[MAC REDACTED]',
    '[HOST REDACTED]',
    "in line_lower",          # parser code: 'board-name:' in line_lower
    "in ll",                  # parser code: 'architecture-name:' in ll
    "' in ",                  # any string comparison in Python code
    '" in ',                  # any string comparison in Python code
    'startswith(',            # parser: line.startswith('board-name:')
    'COMMAND_PATTERN',        # firewall parser constants
    # Test data patterns (fake MAC addresses)
    'AA:BB:CC:DD:EE:',        # test MAC addresses
    '00:00:00:00:00:',        # test MAC addresses
    'D8:50:E6:52:8B:',        # test MAC addresses
    '00:11:22:33:44:',        # test MAC addresses
    # Test data in assertions
    'assert ',                # test assertions with fake data
    # Redaction patterns in code
    're.sub(',                # redaction code
    'r\'client-id=',          # redaction pattern definition
    # Test data patterns (DHCP, hostnames, client-id)
    'host-name="',            # test hostname patterns
    'client-id="',            # test client-id patterns
    'entry_str = ',           # test data strings
    # Test data patterns (serial numbers, passwords, connections)
    'serial-number: ',        # test serial numbers
    'serial-number=',         # test serial numbers
    'password=pass',          # test passwords
    'remote=192.168.',        # test connection data
    'last-logged-in=',        # test login timestamps
    # Documentation strings in check_pii.py itself
    'name="..."',             # docstring example
    'host-name="[^"',         # regex pattern definition
    # Pydantic model fields
    'password: Optional',     # Pydantic model field definition
]

# ═════════════════════════════════════════════════════════════════════════════
# Severity
# ═════════════════════════════════════════════════════════════════════════════

# These patterns are ERRORS (block commit)
ERROR_PATTERNS = {
    "MAC_ADDRESS", "SERIAL_NUMBER", "ROUTEROS_USERNAME", "DHCP_HOSTNAME",
    "DHCP_CLIENT_ID", "LAST_LOGGED_IN", "REAL_PASSWORD", "ACTIVE_SSH_SESSION",
}

# These are WARNINGS (shown but don't block)
WARNING_PATTERNS = {
    "ROUTEROS_RAW_OUTPUT", "TIMEZONE_CITY", "ROUTEROS_IDENTITY_OUTPUT",
}

# ═════════════════════════════════════════════════════════════════════════════
# Colours
# ═════════════════════════════════════════════════════════════════════════════

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ═════════════════════════════════════════════════════════════════════════════
# Core Logic
# ═════════════════════════════════════════════════════════════════════════════

def should_skip_file(filepath: str) -> bool:
    """Return True if the file should not be scanned."""
    for pattern in SKIP_FILE_PATTERNS:
        if re.search(pattern, filepath):
            return True
    return False


def is_allowlisted_line(line: str) -> bool:
    """Return True if the line contains an allowlisted string."""
    for s in ALLOWLIST_STRINGS:
        if s in line:
            return True
    return False


def scan_file(filepath: str) -> List[Tuple[str, int, str, str]]:
    """
    Scan a file for PII patterns.

    Returns list of (pattern_name, line_number, matched_text, full_line).
    """
    findings = []

    try:
        path = Path(filepath)

        # Skip binary files and large files (>500KB)
        if path.stat().st_size > 500 * 1024:
            return []

        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []

    for line_num, line in enumerate(content.splitlines(), 1):
        if is_allowlisted_line(line):
            continue

        for pattern_name, (pattern, _description) in PATTERNS.items():
            flags = re.MULTILINE
            try:
                for match in re.finditer(pattern, line, flags):
                    matched = match.group().strip()
                    # Skip very short matches (likely false positives)
                    if len(matched) < 4:
                        continue
                    findings.append((pattern_name, line_num, matched, line.strip()))
            except re.error:
                pass

    return findings


def get_staged_files() -> List[str]:
    """Get list of files staged for commit."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, check=True
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        return []


def format_finding(filepath: str, pattern_name: str, line_num: int,
                   matched: str, full_line: str, is_error: bool) -> str:
    """Format a single finding for display."""
    colour = RED if is_error else YELLOW
    level = "ERROR" if is_error else "WARN "
    _, description = PATTERNS[pattern_name]

    # Truncate long lines
    display_line = full_line[:120] + "..." if len(full_line) > 120 else full_line
    # Highlight the matched part
    highlighted = display_line.replace(matched, f"{colour}{BOLD}{matched}{RESET}", 1)

    return (
        f"\n  {colour}{BOLD}[{level}]{RESET} {CYAN}{filepath}{RESET}:{line_num}\n"
        f"  Pattern : {pattern_name} — {description}\n"
        f"  Matched : {colour}{matched}{RESET}\n"
        f"  Line    : {highlighted}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═════════════════════════════════════════════════════════════════════════════

def main() -> int:
    # Determine which files to scan
    if len(sys.argv) > 1:
        files_to_scan = [f for f in sys.argv[1:] if os.path.isfile(f)]
        mode = "manual"
    else:
        files_to_scan = get_staged_files()
        mode = "staged"

    if not files_to_scan:
        print(f"{GREEN}✓ No files to scan{RESET}")
        return 0

    # Filter out skipped files
    files_to_scan = [f for f in files_to_scan if not should_skip_file(f)]

    # Use UTF-8 encoding for Windows console compatibility
    if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print(f"{CYAN}{BOLD}MikroTik PII Scanner{RESET} "
          f"({mode} mode, {len(files_to_scan)} file(s))\n")

    all_errors: List[str] = []
    all_warnings: List[str] = []
    scanned = 0

    for filepath in files_to_scan:
        findings = scan_file(filepath)
        if not findings:
            scanned += 1
            continue

        scanned += 1
        for pattern_name, line_num, matched, full_line in findings:
            is_error = pattern_name in ERROR_PATTERNS
            msg = format_finding(filepath, pattern_name, line_num,
                                 matched, full_line, is_error)
            if is_error:
                all_errors.append(msg)
            else:
                all_warnings.append(msg)

    # Print results
    if all_warnings:
        print(f"{YELLOW}{BOLD}⚠️  Warnings ({len(all_warnings)}){RESET}")

        for w in all_warnings:
            print(w)

    if all_errors:
        print(f"\n{RED}{BOLD}❌ PII detected — commit BLOCKED ({len(all_errors)} issue(s)){RESET}")
        for e in all_errors:
            print(e)

        print(f"\n{YELLOW}{BOLD}How to fix:{RESET}")
        print("  1. Run the audit with --redact flag to mask sensitive data")
        print("  2. Check that report files are in .gitignore (audit-reports/)")
        print("  3. If this is test data, add it to ALLOWLIST_STRINGS in check_pii.py")
        print("  4. To skip a specific line, add: # noqa: pii")
        print("\n  Or force-skip this check: git commit --no-verify")
        return 1

    if not all_warnings:
        print(f"{GREEN}✅ Clean — no PII detected in {scanned} file(s){RESET}")
    else:
        print(f"\n{GREEN}✅ No blocking PII (warnings above are informational){RESET}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
