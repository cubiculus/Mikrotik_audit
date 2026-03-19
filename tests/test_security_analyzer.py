"""Tests for security_analyzer module."""

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

    # ===== USER MANAGEMENT TESTS =====

    def test_default_admin_user_detection(self):
        """Test detection of default admin user."""
        results = [
            CommandResult(
                index=1,
                command="/user print",
                stdout='name=admin group=full disabled=no',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "User Management" for issue in issues)
        assert any("admin" in issue.finding.lower() for issue in issues)

    def test_admin_user_renamed_no_issue(self):
        """Test that renamed admin user doesn't trigger warning."""
        results = [
            CommandResult(
                index=1,
                command="/user print",
                stdout='name=administrator group=full disabled=no',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        # Should not trigger default admin name warning
        admin_issues = [i for i in issues if i.category == "User Management" and "default admin name" in i.finding.lower()]
        assert len(admin_issues) == 0

    # ===== FIREWALL TESTS =====

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
        assert any("no firewall" in issue.finding.lower() for issue in issues)

    def test_open_ssh_port_detection(self):
        """Test detection of open SSH port on input chain."""
        results = [
            CommandResult(
                index=1,
                command="/ip firewall filter print",
                stdout='chain=input action=accept dst-port=22',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "Firewall" and "ssh" in issue.finding.lower() for issue in issues)

    def test_telnet_port_detection(self):
        """Test detection of Telnet port (23) exposure."""
        results = [
            CommandResult(
                index=1,
                command="/ip firewall filter print",
                stdout='chain=input action=accept dst-port=23',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "Firewall" and "telnet" in issue.finding.lower() for issue in issues)

    # ===== NAT TESTS =====

    def test_broad_masquerade_rule_detection(self):
        """Test detection of broad NAT masquerade rules."""
        results = [
            CommandResult(
                index=1,
                command="/ip firewall nat print",
                stdout='src-address=0.0.0.0/0 action=masquerade',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "NAT" for issue in issues)
        assert any("masquerade" in issue.finding.lower() for issue in issues)

    def test_rdp_port_forwarding_detection(self):
        """Test detection of RDP port forwarding."""
        results = [
            CommandResult(
                index=1,
                command="/ip firewall nat print",
                stdout='dst-port=3389 action=dst-nat',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "NAT" and "rdp" in issue.finding.lower() for issue in issues)

    # ===== SERVICES TESTS =====

    def test_telnet_service_enabled(self):
        """Test detection of enabled Telnet service."""
        results = [
            CommandResult(
                index=1,
                command="/ip service print",
                stdout='name=telnet disabled=no',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "Services" and "telnet" in issue.finding.lower() for issue in issues)
        assert any(issue.severity == "High" for issue in issues)

    def test_ftp_service_enabled(self):
        """Test detection of enabled FTP service."""
        results = [
            CommandResult(
                index=1,
                command="/ip service print",
                stdout='name=ftp disabled=no',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "Services" and "ftp" in issue.finding.lower() for issue in issues)

    # ===== SSH TESTS =====

    def test_ssh_strong_crypto_disabled(self):
        """Test detection of disabled SSH strong crypto."""
        results = [
            CommandResult(
                index=1,
                command="/ip ssh print",
                stdout='strong-crypto: no',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "SSH" and "strong crypto" in issue.finding.lower() for issue in issues)
        assert any(issue.severity == "High" for issue in issues)

    def test_ssh_default_port_detection(self):
        """Test detection of SSH using default port 22."""
        results = [
            CommandResult(
                index=1,
                command="/ip ssh print",
                stdout='port=22',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "SSH" and "port 22" in issue.finding.lower() for issue in issues)

    # ===== PPP/VPN TESTS =====

    def test_ppp_default_profile(self):
        """Test detection of default PPP profile usage."""
        results = [
            CommandResult(
                index=1,
                command="/ppp profile print",
                stdout='name="default" local-address=0.0.0.0 remote-address=0.0.0.0',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "PPP" and "Default PPP profile" in issue.finding for issue in issues)

    def test_ppp_admin_name(self):
        """Test detection of PPP secret with admin name."""
        results = [
            CommandResult(
                index=1,
                command="/ppp secret print",
                stdout='name=admin',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "PPP" and "admin" in issue.finding.lower() for issue in issues)

    # ===== DNS TESTS =====

    def test_dns_remote_requests_enabled(self):
        """Test detection of DNS remote requests."""
        results = [
            CommandResult(
                index=1,
                command="/ip dns print",
                stdout='allow-remote-requests: yes',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "DNS" for issue in issues)

    # ===== WIREGUARD TESTS =====

    def test_wireguard_allows_all_addresses(self):
        """Test detection of WireGuard peer allowing all addresses."""
        results = [
            CommandResult(
                index=1,
                command="/interface wireguard peers print",
                stdout='allowed-address=0.0.0.0/0',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "WireGuard" for issue in issues)

    # ===== CERTIFICATE TESTS =====

    def test_weak_certificate_key_size(self):
        """Test detection of weak certificate key size."""
        results = [
            CommandResult(
                index=1,
                command="/system certificate print",
                stdout='key-size=1024',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) > 0
        assert any(issue.category == "Certificates" and "key size" in issue.finding.lower() for issue in issues)

    # ===== GENERAL TESTS =====

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
                command="/ip service print",
                stdout='name=telnet disabled=no',  # Triggers telnet issue
                has_error=False
            ),
            CommandResult(
                index=3,
                command="/user print",
                stdout='name=admin disabled=no',  # Triggers admin issue
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        assert len(issues) >= 3


# ===== FIX COMMANDS TESTS =====

class TestFixCommands:
    """Tests for fix_commands feature."""

    def test_fix_commands_field_exists(self):
        """Test that SecurityIssue has fix_commands field."""
        issue = SecurityIssue(
            severity="High",
            category="SSH",
            finding="Test issue",
            recommendation="Fix it",
            fix_commands=["/command1", "/command2"]
        )
        assert issue.fix_commands == ["/command1", "/command2"]

    def test_fix_commands_empty_by_default(self):
        """Test that fix_commands is empty by default."""
        issue = SecurityIssue(
            severity="Medium",
            category="Test",
            finding="Test",
            recommendation="Fix"
        )
        assert issue.fix_commands == []

    def test_ssh_strong_crypto_fix_commands(self):
        """Test that SSH strong crypto issue has fix commands."""
        results = [
            CommandResult(
                index=1,
                command="/ip ssh print",
                stdout='strong-crypto: no',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        ssh_issues = [i for i in issues if "strong crypto" in i.finding.lower()]
        assert len(ssh_issues) > 0
        assert len(ssh_issues[0].fix_commands) > 0
        assert "/ip ssh set strong-crypto=yes" in ssh_issues[0].fix_commands

    def test_telnet_service_fix_commands(self):
        """Test that Telnet service issue has fix commands."""
        results = [
            CommandResult(
                index=1,
                command="/ip service print",
                stdout='name=telnet disabled=no',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        telnet_issues = [i for i in issues if "telnet" in i.finding.lower()]
        assert len(telnet_issues) > 0
        assert len(telnet_issues[0].fix_commands) > 0
        assert "/ip service disable telnet" in telnet_issues[0].fix_commands

    def test_ftp_service_fix_commands(self):
        """Test that FTP service issue has fix commands."""
        results = [
            CommandResult(
                index=1,
                command="/ip service print",
                stdout='name=ftp disabled=no',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        ftp_issues = [i for i in issues if "ftp" in i.finding.lower()]
        assert len(ftp_issues) > 0
        assert len(ftp_issues[0].fix_commands) > 0
        assert "/ip service disable ftp" in ftp_issues[0].fix_commands

    def test_no_firewall_rules_fix_commands(self):
        """Test that empty firewall issue has comprehensive fix commands."""
        results = [
            CommandResult(
                index=1,
                command="/ip firewall filter print",
                stdout="",  # Empty = no rules
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        firewall_issues = [i for i in issues if "no firewall" in i.finding.lower()]
        assert len(firewall_issues) > 0
        assert len(firewall_issues[0].fix_commands) > 5  # Multiple commands for firewall setup
        assert any("chain=input" in cmd for cmd in firewall_issues[0].fix_commands)
        assert any("chain=forward" in cmd for cmd in firewall_issues[0].fix_commands)

    def test_ssh_root_login_fix_commands(self):
        """Test that SSH root login issue has fix commands."""
        results = [
            CommandResult(
                index=1,
                command="/ip ssh print",
                stdout='allow-root-login=yes',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        root_issues = [i for i in issues if "root login" in i.finding.lower()]
        assert len(root_issues) > 0
        assert len(root_issues[0].fix_commands) > 0
        assert "/ip ssh set allow-root-login=no" in root_issues[0].fix_commands

    def test_http_service_fix_commands(self):
        """Test that HTTP service issue has fix commands."""
        results = [
            CommandResult(
                index=1,
                command="/ip service print",
                stdout='name=www disabled=no',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        http_issues = [i for i in issues if "http" in i.finding.lower() or "www" in i.finding.lower()]
        assert len(http_issues) > 0
        assert len(http_issues[0].fix_commands) > 0
        assert "/ip service disable www" in http_issues[0].fix_commands

    def test_firewall_open_accept_rule_fix_commands(self):
        """Test that open accept rule on WAN has fix commands."""
        results = [
            CommandResult(
                index=1,
                command="/ip firewall filter print",
                stdout='chain=input action=accept in-interface=ether1',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        open_issues = [i for i in issues if "open accept rule" in i.finding.lower()]
        assert len(open_issues) > 0
        assert len(open_issues[0].fix_commands) > 0
        assert any("print where" in cmd for cmd in open_issues[0].fix_commands)

    def test_all_fix_commands_are_strings(self):
        """Test that all fix commands are strings."""
        results = [
            CommandResult(
                index=1,
                command="/ip ssh print",
                stdout='strong-crypto: no allow-root-login=yes',
                has_error=False
            )
        ]
        issues = SecurityAnalyzer.analyze(results)
        for issue in issues:
            for cmd in issue.fix_commands:
                assert isinstance(cmd, str)
                assert len(cmd) > 0
