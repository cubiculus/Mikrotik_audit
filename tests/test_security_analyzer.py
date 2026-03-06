"""Tests for security_analyzer module."""

import pytest
from src.config import CommandResult, SecurityIssue
from src.security_analyzer import SecurityAnalyzer


class TestSecurityAnalyzer:
    """Tests for SecurityAnalyzer."""

    def test_no_issues_with_empty_results(self):
        """Test that empty results return no issues."""
        issues = SecurityAnalyzer.analyze([])
        assert len(issues) == 0

    def test_no_issues_with_successful_commands(self):
        """Test that normal successful commands return no issues."""
        results = [
            CommandResult(
                index=1,
                command="/system identity print",
                stdout="name: TestRouter",
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) == 0

    def test_skips_error_results(self):
        """Test that commands with errors are skipped."""
        results = [
            CommandResult(
                index=1,
                command="/user print",
                stdout="",
                stderr="Connection failed",
                has_error=True
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) == 0

    def test_default_admin_user_detection(self):
        """Test detection of default admin user."""
        # Condition: "admin" in out AND "disabled" not in out AND "name=admin" in out
        results = [
            CommandResult(
                index=1,
                command="/user print",
                stdout="name=admin group=full",  # "admin" present, "disabled" not present, "name=admin" present
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "User Management" for issue in issues)

    def test_no_firewall_rules_detection(self):
        """Test detection of empty firewall configuration."""
        results = [
            CommandResult(
                index=1,
                command="/ip firewall filter print",
                stdout="",  # Empty output = no rules
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "Firewall" for issue in issues)

    def test_broad_masquerade_rule_detection(self):
        """Test detection of broad NAT masquerade rules."""
        results = [
            CommandResult(
                index=1,
                command="/ip firewall nat print",
                stdout="action=masquerade 0.0.0.0/0",
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "NAT" for issue in issues)

    def test_ssh_disabled_detection(self):
        """Test detection of disabled SSH."""
        results = [
            CommandResult(
                index=1,
                command="/ip ssh print",
                stdout="enabled: no\ndisabled=yes",
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "SSH" for issue in issues)

    def test_security_issue_properties(self):
        """Test SecurityIssue model properties."""
        issue = SecurityIssue(
            severity="High",
            category="Firewall",
            finding="No firewall rules",
            recommendation="Configure firewall"
        )
        assert issue.severity == "High"
        assert issue.category == "Firewall"
        assert issue.finding == "No firewall rules"
        assert issue.recommendation == "Configure firewall"

    def test_security_issue_finding_description_sync(self):
        """Test that finding and description are synchronized."""
        # With description only - provide all required fields
        issue1 = SecurityIssue(
            severity="Medium",
            category="Test",
            description="Test description",
            recommendation="Fix it"
        )
        assert issue1.finding == "Test description"

        # With finding only
        issue2 = SecurityIssue(
            severity="Medium",
            category="Test",
            finding="Test finding",
            recommendation="Fix it"
        )
        assert issue2.description == "Test finding"

    def test_multiple_issues(self):
        """Test detection of multiple security issues."""
        results = [
            CommandResult(
                index=1,
                command="/ip firewall filter print",
                stdout="",  # Triggers firewall issue
                has_error=False
            ),
            CommandResult(
                index=2,
                command="/ip ssh print",
                stdout="disabled=yes",  # Triggers SSH issue
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) >= 2
