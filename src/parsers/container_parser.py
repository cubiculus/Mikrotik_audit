"""Parser for container information."""

import logging
import re
from typing import List, Tuple

from src.models import Container, NetworkOverview

logger = logging.getLogger(__name__)

# Precompiled regular expressions
# Match container header line: index followed by optional flags
# Flags: X - stopped, D - disabled, R - running, S - seccomp, A - apparmor, I - iptables
# RouterOS v7.22+ format: " 0 R ;;; comment" or " 0  R  name=..."
CONTAINER_HEADER_PATTERN = re.compile(r"^\s*(\d+)\s+([XDRSAI]*)\s*(.*)")
NEW_CONTAINER_PATTERN = re.compile(r"^\s*\d+")
INDENTED_PATTERN = re.compile(r"^\s{2,}")  # Changed from 3+ to 2+ for RouterOS v7.22+

# Container field mapping
CONTAINER_FIELD_MAP = {
    'name': 'name',
    'remote-image': 'image',
    'root-directory': 'root_directory',
    'interface': 'interface',
    'ip-address': 'ip_address',
    'creation-time': 'created',
    'started': 'started',
    'uptime': 'uptime'
}


def _parse_container_param_cached(param_str: str) -> tuple:
    """Cached container parameter parsing."""
    if '=' not in param_str:
        return None, None
    try:
        key, value = param_str.split('=', 1)
        # Remove quotes from value
        clean_value = value.strip().strip("'\"")
        return key, clean_value
    except ValueError:
        return None, None


def _set_container_field(container: Container, key: str, value: str) -> None:
    """Set container field based on key."""
    field = CONTAINER_FIELD_MAP.get(key)
    if field and hasattr(container, field):
        setattr(container, field, value)
    if key == 'root-directory':
        container.root_dir = value


def parse_containers(results: List) -> Tuple[List[Container], NetworkOverview]:
    """Parse container results - specialized parser for containers."""
    containers: List[Container] = []
    overview = NetworkOverview()

    if not results or results[0].has_error:
        logger.warning("No container data available")
        return containers, overview

    lines = results[0].stdout.split('\n')
    total_lines = len(lines)
    i = 0

    while i < total_lines:
        line = lines[i]

        # Find container lines with index number
        header_match = CONTAINER_HEADER_PATTERN.match(line)
        if header_match:
            # Check if this line has container parameters (name=, remote-image=, etc.)
            rest_of_line = header_match.group(3).strip() if header_match.group(3) else ''
            flags = header_match.group(2) or ''

            # RouterOS v7.22+: First line may only have comment, params on next lines
            # Don't skip - process all container headers
            status = "running" if 'R' in flags else "stopped"

            current_container = Container()
            current_container.status = status

            logger.debug(f"Found container header at line {i}: flags={flags}, status={status}")

            # Parse parameters from the same line (after flags) if present
            if '=' in rest_of_line:
                for part in rest_of_line.split():
                    key, value = _parse_container_param_cached(part)
                    if key and value:
                        _set_container_field(current_container, key, value)

            # Parse container parameters from following lines
            j = i + 1
            while j < total_lines:
                next_line = lines[j]
                next_line_stripped = next_line.strip()

                # RouterOS v7.22+ format: continuation lines start with 4+ spaces
                # New container: line starts with single space + number
                if next_line.startswith(' ') and not next_line.startswith('    '):
                    # Could be a new container (1-3 spaces indent)
                    if NEW_CONTAINER_PATTERN.match(next_line_stripped):
                        break
                elif not next_line.startswith(' '):
                    # No indent at all - could be new section
                    if NEW_CONTAINER_PATTERN.match(next_line_stripped):
                        break

                # Parse parameters (indented lines with =)
                if '=' in next_line_stripped:
                    for part in next_line_stripped.split():
                        key, value = _parse_container_param_cached(part)
                        if key and value:
                            _set_container_field(current_container, key, value)

                j += 1

            # Add container if it has a name
            if current_container.name:
                containers.append(current_container)
                logger.debug(f"Parsed container: {current_container.name} -> {current_container.status}")

            i = j
        else:
            i += 1

    overview.containers_total = len(containers)
    overview.containers_running = sum(1 for c in containers if c.status == "running")

    return containers, overview
