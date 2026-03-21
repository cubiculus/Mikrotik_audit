"""RSC (RouterOS Script) file parser for offline analysis.

This module parses RouterOS configuration files exported via:
  /export hide-sensitive
  /export verbose
  /export compact

The RSC format differs from 'print' format:
  - Commands use 'add' syntax: add chain=input action=accept
  - Parameters use '=' not ':': src-address=192.168.1.1
  - Comments start with '#'
  - Multi-line values use backslash continuation

Offline mode limitations:
  - No live data (leases, ARP, logs, traffic stats)
  - No uptime/health information
  - No dynamic rules (marked with 'D' flag)
"""

import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from src.config import CommandResult

logger = logging.getLogger(__name__)


@dataclass
class RSCCommand:
    """Parsed RSC command."""
    line_number: int
    raw_line: str
    command_type: str  # 'add', 'set', 'remove', 'print', etc.
    path: str  # e.g., '/ip firewall filter'
    parameters: Dict[str, str] = field(default_factory=dict)
    comment: str = ""
    is_comment: bool = False
    is_empty: bool = False


class RSCParser:
    """
    Parser for RouterOS configuration files (.rsc).

    Usage:
        parser = RSCParser()
        commands = parser.parse_file('config.rsc')
        # Convert to CommandResult for analysis
        results = parser.to_command_results(commands)
    """

    def __init__(self):
        self.commands: List[RSCCommand] = []
        self.parse_errors: List[Tuple[int, str, str]] = []  # (line, error, content)

    def parse_file(self, filepath: str) -> List[RSCCommand]:
        """
        Parse RSC file.

        Args:
            filepath: Path to .rsc file

        Returns:
            List of parsed commands
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"RSC file not found: {filepath}")

        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()

        return self.parse_content(content)

    def parse_content(self, content: str) -> List[RSCCommand]:
        """
        Parse RSC content from string.

        Args:
            content: RSC file content

        Returns:
            List of parsed commands
        """
        self.commands = []
        self.parse_errors = []

        lines = content.split('\n')
        continued_line = ""
        start_line_num = 0

        for i, line in enumerate(lines, 1):
            # Handle line continuation (backslash at end)
            if line.rstrip().endswith('\\'):
                if not continued_line:
                    start_line_num = i
                continued_line += line.rstrip()[:-1] + " "
                continue
            elif continued_line:
                line = continued_line + line
                i = start_line_num
                continued_line = ""

            command = self._parse_line(i, line)
            if command:
                self.commands.append(command)

        return self.commands

    def _parse_line(self, line_num: int, line: str) -> Optional[RSCCommand]:
        """Parse a single line."""
        original_line = line
        line = line.strip()

        # Empty line
        if not line:
            return RSCCommand(
                line_number=line_num,
                raw_line=original_line,
                command_type="",
                path="",
                is_empty=True
            )

        # Comment line
        if line.startswith('#'):
            return RSCCommand(
                line_number=line_num,
                raw_line=original_line,
                command_type="comment",
                path="",
                comment=line[1:].strip(),
                is_comment=True
            )

        # Parse command
        try:
            return self._parse_command(line_num, original_line, line)
        except Exception as e:
            self.parse_errors.append((line_num, str(e), line))
            logger.debug(f"Parse error at line {line_num}: {e} - {line}")
            return None

    def _parse_command(self, line_num: int, original: str, line: str) -> RSCCommand:
        """Parse a command line."""
        # Extract comment at end of line
        comment = ""
        if '#' in line:
            parts = line.split('#', 1)
            line = parts[0].strip()
            comment = parts[1].strip()

        # Parse command - RouterOS RSC format:
        # /ip firewall filter add chain=input action=accept
        # Parts: ['/ip', 'firewall', 'filter', 'add', 'chain=input', ...]

        parts = line.split()
        if not parts:
            return RSCCommand(
                line_number=line_num,
                raw_line=original,
                command_type="",
                path="",
                is_empty=True
            )

        # Build path from all parts starting with / until we hit a command keyword
        command_keywords = {'add', 'set', 'remove', 'print', 'disable', 'enable', 'move', 'clone', 'find', 'resolve'}

        path_parts = []
        cmd_start_idx = 0

        for i, part in enumerate(parts):
            if part.startswith('/'):
                # Start of new path
                path_parts = [part]
            elif path_parts and part not in command_keywords:
                # Continue path
                path_parts.append(part)
            elif part in command_keywords:
                # Found command keyword
                cmd_start_idx = i
                break
            else:
                # Unknown part after path
                cmd_start_idx = i
                break

        # Build full path
        path = ' '.join(path_parts) if path_parts else ""

        # Get command type
        command_type = parts[cmd_start_idx] if cmd_start_idx < len(parts) else ""

        # Parse parameters from remaining parts
        params_str = ' '.join(parts[cmd_start_idx + 1:]) if cmd_start_idx + 1 < len(parts) else ""
        parameters = self._parse_parameters(params_str)

        return RSCCommand(
            line_number=line_num,
            raw_line=original,
            command_type=command_type,
            path=path,
            parameters=parameters,
            comment=comment
        )

    def _parse_parameters(self, params_str: str) -> Dict[str, str]:
        """Parse command parameters."""
        parameters = {}

        # Match key=value or key="value with spaces"
        pattern = r'(\w+(?:-\w+)*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|(\S+))'

        for match in re.finditer(pattern, params_str):
            key = match.group(1)
            # Value can be in group 2 (double quotes), 3 (single quotes), or 4 (unquoted)
            value = match.group(2) or match.group(3) or match.group(4) or ""
            parameters[key] = value

        return parameters

    def to_command_results(self) -> List[CommandResult]:
        """
        Convert parsed commands to CommandResult format for analysis.

        This allows using existing analyzers (SecurityAnalyzer, ConflictAnalyzer,
        IoCAnalyzer) on offline configurations.

        Returns:
            List of CommandResult objects
        """
        results = []

        # Group commands by path for simulation
        commands_by_path: Dict[str, List[RSCCommand]] = {}
        for cmd in self.commands:
            if cmd.path and not cmd.is_comment and not cmd.is_empty:
                if cmd.path not in commands_by_path:
                    commands_by_path[cmd.path] = []
                commands_by_path[cmd.path].append(cmd)

        # Create simulated CommandResult for each path
        for path, cmds in commands_by_path.items():
            # Simulate 'print' output from 'add' commands
            simulated_output = self._simulate_print_output(cmds)

            result = CommandResult(
                index=len(results) + 1,
                command=f"{path} print detail",
                stdout=simulated_output,
                stderr="",
                exit_status=0,
                has_error=False
            )
            results.append(result)

        return results

    def _simulate_print_output(self, commands: List[RSCCommand]) -> str:
        """
        Simulate 'print detail' output from 'add' commands.

        This is a best-effort conversion for analysis purposes.
        """
        lines = []

        for cmd in commands:
            if cmd.command_type == 'add':
                # Convert add command to print-like format
                if cmd.path:
                    # Extract the last part of path as the type
                    type_name = cmd.path.split('/')[-1]
                    lines.append(f"{type_name}:")

                    for key, value in cmd.parameters.items():
                        lines.append(f"    {key}: {value}")

                    if cmd.comment:
                        lines.append(f"    comment: {cmd.comment}")

                    lines.append("")

        return '\n'.join(lines)

    def get_statistics(self) -> Dict:
        """Get parsing statistics."""
        stats = {
            'total_lines': len(self.commands),
            'commands': 0,
            'comments': 0,
            'empty_lines': 0,
            'errors': len(self.parse_errors),
            'paths': set()
        }

        for cmd in self.commands:
            if cmd.is_comment:
                stats['comments'] += 1
            elif cmd.is_empty:
                stats['empty_lines'] += 1
            else:
                stats['commands'] += 1
                if cmd.path:
                    stats['paths'].add(cmd.path)

        stats['paths'] = list(stats['paths'])
        return stats


def parse_rsc_file(filepath: str) -> Tuple[List[CommandResult], Dict]:
    """
    Convenience function to parse RSC file and return results for analysis.

    Args:
        filepath: Path to .rsc file

    Returns:
        Tuple of (list of CommandResult, parsing statistics)
    """
    parser = RSCParser()
    parser.parse_file(filepath)

    results = parser.to_command_results()
    stats = parser.get_statistics()

    logger.info(f"Parsed RSC file: {stats['commands']} commands, {stats['errors']} errors")

    return results, stats


def parse_rsc_content(content: str) -> Tuple[List[CommandResult], Dict]:
    """
    Convenience function to parse RSC content from string.

    Args:
        content: RSC file content as string

    Returns:
        Tuple of (list of CommandResult, parsing statistics)
    """
    parser = RSCParser()
    parser.parse_content(content)

    results = parser.to_command_results()
    stats = parser.get_statistics()

    return results, stats
