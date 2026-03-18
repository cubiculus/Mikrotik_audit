"""Common parser utilities for MikroTik RouterOS output parsing."""

from functools import lru_cache


@lru_cache(maxsize=256)
def parse_key_value_line(line: str) -> dict:
    """
    Parse key=value or key: value line into dictionary.

    Handles RouterOS detail format:
        name=value1 comment="long comment" disabled=no

    Args:
        line: Single line from RouterOS output

    Returns:
        Dictionary of parsed key-value pairs

    Example:
        >>> parse_key_value_line('name=ether1 mtu=1500')
        {'name': 'ether1', 'mtu': '1500'}
    """
    data = {}
    i = 0
    n = len(line)

    while i < n:
        # Skip whitespace
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break

        # Find key
        key_start = i
        while i < n and line[i] not in '=:':
            i += 1

        if i >= n:
            break

        key = line[key_start:i].strip().lower().replace('-', '_')

        # Skip separator
        i += 1

        # Skip whitespace
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break

        # Find value
        if line[i] == '"':
            # Quoted value
            value_start = i + 1
            i = value_start
            while i < n and line[i] != '"':
                i += 1
            value = line[value_start:i]
            i += 1
        else:
            # Unquoted value
            value_start = i
            while i < n and not line[i].isspace():
                i += 1
            value = line[value_start:i]

        data[key] = value

    return data
