"""Parser for container information."""

import logging
import re
from typing import List, Tuple
from functools import lru_cache

from src.models import Container, NetworkOverview

logger = logging.getLogger(__name__)

# Precompiled regular expressions
# Match container header line: index followed by optional flags
# Flags: X - stopped, D - disabled, R - running, S - seccomp, A - apparmor, I - iptables
CONTAINER_HEADER_PATTERN = re.compile(r"^\s*(\d+)\s+([XDRSAI]*)\s*(.*)")
NEW_CONTAINER_PATTERN = re.compile(r"^\s*\d+")
INDENTED_PATTERN = re.compile(r"^\s{3,}")

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


@lru_cache(maxsize=128)
def _parse_container_param_cached(param_str: str) -> tuple:
    """Cached container parameter parsing."""
    if '=' not in param_str:
        return None, None
    try:
        key, value = param_str.split('=', 1)
        return key, value.strip("'")
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
            
            # Skip lines that don't have container data (just index with flags)
            if not rest_of_line or '=' not in rest_of_line:
                i += 1
                continue

            flags = header_match.group(2) or ''
            status = "running" if 'R' in flags else "stopped"

            current_container = Container()
            current_container.status = status

            logger.debug(f"Found container with flags: {flags}, status: {status}")

            # Parse parameters from the same line (after flags)
            if '=' in rest_of_line:
                for part in rest_of_line.split():
                    key, value = _parse_container_param_cached(part)
                    if key and value:
                        _set_container_field(current_container, key, value)

            # Parse container parameters from following lines
            j = i + 1
            while j < total_lines:
                next_line = lines[j].strip()

                # New container (starts with number)
                if NEW_CONTAINER_PATTERN.match(next_line) and '=' not in next_line:
                    break

                # Parse parameters (indented or containing =)
                if INDENTED_PATTERN.match(lines[j]) or ('=' in next_line and not NEW_CONTAINER_PATTERN.match(next_line)):
                    for part in next_line.split():
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