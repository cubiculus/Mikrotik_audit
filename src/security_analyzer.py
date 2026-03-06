"""Security analyzer for MikroTik RouterOS."""

import logging
from typing import List, Callable
from src.config import CommandResult, SecurityIssue

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Analyzes command results for security issues."""

    # Security rules: (command_pattern, severity, category, finding, recommendation)
    SECURITY_RULES: List[dict] = [
        {
            "command": "/user print",
            "checks": [
                {
                    "condition": lambda out: "admin" in out and "disabled" not in out and "name=admin" in out,
                    "severity": "High",
                    "category": "User Management",
                    "finding": "Default admin user may be active",
                    "recommendation": "Change default admin password or disable the account"
                }
            ]
        },
        {
            "command": "/ip firewall filter print",
            "checks": [
                {
                    "condition": lambda out: len(out.strip()) < 10,
                    "severity": "High",
                    "category": "Firewall",
                    "finding": "No firewall rules configured",
                    "recommendation": "Configure appropriate firewall rules"
                }
            ]
        },
        {
            "command": "/ip firewall nat print",
            "checks": [
                {
                    "condition": lambda out: "0.0.0.0/0" in out and "action=masquerade" in out.lower(),
                    "severity": "Medium",
                    "category": "NAT",
                    "finding": "Broad masquerade rule detected",
                    "recommendation": "Review NAT rules for specificity"
                }
            ]
        },
        {
            "command": "/ip ssh print",
            "checks": [
                {
                    "condition": lambda out: "disabled=yes" in out.lower(),
                    "severity": "Medium",
                    "category": "SSH",
                    "finding": "SSH appears to be disabled",
                    "recommendation": "Enable SSH for secure remote management"
                }
            ]
        }
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
