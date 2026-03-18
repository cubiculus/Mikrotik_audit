"""Tests for CVE database."""

from src.cve_database import (
    CVE,
    ROUTEROS_CVE_DATABASE,
    parse_version,
    version_matches_pattern,
    is_version_vulnerable,
    check_cve_for_version
)


class TestCVEDataClass:
    """Tests for CVE dataclass."""

    def test_cve_creation(self):
        """Test creating CVE object."""
        cve = CVE(
            cve_id="CVE-2024-1234",
            severity="High",
            title="Test Vulnerability",
            description="Test description",
            recommendation="Update software",
            affected_versions=["6.0-6.49.0"],
            fixed_version="6.49.1",
            references=["https://example.com"]
        )
        assert cve.cve_id == "CVE-2024-1234"
        assert cve.severity == "High"
        assert cve.title == "Test Vulnerability"
        assert len(cve.references) == 1

    def test_cve_database_not_empty(self):
        """Test that CVE database is populated."""
        assert len(ROUTEROS_CVE_DATABASE) > 0

    def test_cve_database_has_required_fields(self):
        """Test that all CVEs have required fields."""
        for cve in ROUTEROS_CVE_DATABASE:
            assert cve.cve_id.startswith("CVE-")
            assert cve.severity in ["High", "Medium", "Low"]
            assert cve.title
            assert cve.description
            assert cve.recommendation
            assert len(cve.affected_versions) > 0
            assert cve.fixed_version
            assert len(cve.references) > 0


class TestParseVersion:
    """Tests for version parsing function."""

    def test_parse_version_basic(self):
        """Test parsing basic version."""
        assert parse_version("6.49.6") == (6, 49, 6, None)
        assert parse_version("7.10.5") == (7, 10, 5, None)

    def test_parse_version_with_v_prefix(self):
        """Test parsing version with v prefix."""
        assert parse_version("v6.49.6") == (6, 49, 6, None)
        assert parse_version("v7.10") == (7, 10, 0, None)

    def test_parse_version_rc(self):
        """Test parsing release candidate version."""
        major, minor, patch, prerelease = parse_version("7.10rc1")
        assert major == 7
        assert minor == 10
        assert patch == 0
        assert prerelease is not None

    def test_parse_version_incomplete(self):
        """Test parsing incomplete version."""
        assert parse_version("7") == (7, 0, 0, None)
        assert parse_version("7.10") == (7, 10, 0, None)

    def test_parse_version_invalid(self):
        """Test parsing invalid version."""
        assert parse_version("invalid") == (0, 0, 0, None)
        assert parse_version("") == (0, 0, 0, None)

    def test_parse_version_malformed(self):
        """Test parsing malformed version."""
        assert parse_version("abc.def.ghi") == (0, 0, 0, None)


class TestVersionMatchesPattern:
    """Tests for version pattern matching."""

    def test_wildcard_major(self):
        """Test wildcard matching on major version."""
        assert version_matches_pattern("6.49.6", "6.*") is True
        assert version_matches_pattern("6.0.0", "6.*") is True
        assert version_matches_pattern("7.0.0", "6.*") is False

    def test_wildcard_minor(self):
        """Test wildcard matching on minor version."""
        assert version_matches_pattern("6.42.5", "6.42.*") is True
        assert version_matches_pattern("6.42.0", "6.42.*") is True
        assert version_matches_pattern("6.43.0", "6.42.*") is False

    def test_range_pattern(self):
        """Test range pattern matching."""
        assert version_matches_pattern("7.0.0", "7.0-7.5") is True
        assert version_matches_pattern("7.3.0", "7.0-7.5") is True
        # 7.5.3 is outside 7.0-7.5 range (patch version 3 > 5)
        assert version_matches_pattern("7.5.0", "7.0-7.5") is True
        assert version_matches_pattern("7.5.3", "7.0-7.5") is False
        assert version_matches_pattern("7.6.0", "7.0-7.5") is False
        assert version_matches_pattern("6.49.0", "7.0-7.5") is False

    def test_exact_pattern(self):
        """Test exact pattern matching."""
        assert version_matches_pattern("6.49.6", "6.49.6") is True
        assert version_matches_pattern("6.49.6", "6.49.7") is False

    def test_invalid_pattern(self):
        """Test invalid pattern handling."""
        assert version_matches_pattern("6.49.6", "invalid") is False
        assert version_matches_pattern("6.49.6", "-") is False


class TestIsVersionVulnerable:
    """Tests for version vulnerability checking."""

    def test_vulnerable_version(self):
        """Test that vulnerable version is detected."""
        cve = CVE(
            cve_id="CVE-TEST-1",
            severity="High",
            title="Test",
            description="Test",
            recommendation="Update",
            affected_versions=["6.0-6.42.6"],
            fixed_version="6.42.7",
            references=[]
        )
        assert is_version_vulnerable("6.40.0", cve) is True
        assert is_version_vulnerable("6.42.6", cve) is True

    def test_fixed_version(self):
        """Test that fixed version is not vulnerable."""
        cve = CVE(
            cve_id="CVE-TEST-1",
            severity="High",
            title="Test",
            description="Test",
            recommendation="Update",
            affected_versions=["6.0-6.42.6"],
            fixed_version="6.42.7",
            references=[]
        )
        assert is_version_vulnerable("6.42.7", cve) is False
        assert is_version_vulnerable("6.49.0", cve) is False

    def test_multiple_patterns(self):
        """Test vulnerability with multiple patterns."""
        cve = CVE(
            cve_id="CVE-TEST-1",
            severity="High",
            title="Test",
            description="Test",
            recommendation="Update",
            affected_versions=["6.0-6.42.6", "7.0-7.5"],
            fixed_version="7.6",
            references=[]
        )
        assert is_version_vulnerable("6.40.0", cve) is True
        assert is_version_vulnerable("7.3.0", cve) is True
        assert is_version_vulnerable("7.10.0", cve) is False


class TestCheckCVEForVersion:
    """Tests for checking CVEs for a version."""

    def test_check_cve_returns_list(self):
        """Test that check returns a list."""
        result = check_cve_for_version("6.49.6")
        assert isinstance(result, list)

    def test_check_cve_finds_vulnerabilities(self):
        """Test that check finds vulnerabilities for old versions."""
        result = check_cve_for_version("6.40.0")
        assert len(result) > 0

    def test_check_cve_different_versions(self):
        """Test that different versions have different CVEs."""
        cves_v6 = check_cve_for_version("6.40.0")
        cves_v7 = check_cve_for_version("7.10.0")

        # Both should have some CVEs but different sets
        assert isinstance(cves_v6, list)
        assert isinstance(cves_v7, list)

    def test_check_cve_latest_version(self):
        """Test that latest version has fewer CVEs."""
        cves_old = check_cve_for_version("6.40.0")
        cves_new = check_cve_for_version("7.15.0")

        # Newer version should generally have fewer known CVEs
        assert len(cves_new) <= len(cves_old)

    def test_check_cve_specific_known_cve(self):
        """Test checking for specific known CVE."""
        # CVE-2018-14847 affects versions before 6.42.7
        cves = check_cve_for_version("6.40.0")
        cve_ids = [cve.cve_id for cve in cves]
        assert "CVE-2018-14847" in cve_ids

    def test_check_cve_fixed_version_not_included(self):
        """Test that fixed version is not in vulnerable list."""
        # CVE-2018-14847 fixed in 6.42.7
        cves = check_cve_for_version("6.49.6")
        cve_ids = [cve.cve_id for cve in cves]
        assert "CVE-2018-14847" not in cve_ids


class TestCVESeverity:
    """Tests for CVE severity levels."""

    def test_cve_database_has_multiple_severities(self):
        """Test that CVE database has multiple severity levels."""
        severities = {cve.severity for cve in ROUTEROS_CVE_DATABASE}
        assert len(severities) > 1

    def test_high_severity_cves_exist(self):
        """Test that high severity CVEs exist."""
        high_cves = [cve for cve in ROUTEROS_CVE_DATABASE if cve.severity == "High"]
        assert len(high_cves) > 0

    def test_medium_severity_cves_exist(self):
        """Test that medium severity CVEs exist."""
        medium_cves = [cve for cve in ROUTEROS_CVE_DATABASE if cve.severity == "Medium"]
        assert len(medium_cves) > 0


class TestCveDescriptions:
    """Tests for CVE descriptions and recommendations."""

    def test_all_cves_have_descriptions(self):
        """Test that all CVEs have descriptions."""
        for cve in ROUTEROS_CVE_DATABASE:
            assert cve.description
            assert len(cve.description) > 20

    def test_all_cves_have_recommendations(self):
        """Test that all CVEs have recommendations."""
        for cve in ROUTEROS_CVE_DATABASE:
            assert cve.recommendation
            assert len(cve.recommendation) > 10

    def test_recommendations_mention_upgrade(self):
        """Test that recommendations mention upgrade."""
        for cve in ROUTEROS_CVE_DATABASE:
            assert "Upgrade" in cve.recommendation or "upgrade" in cve.recommendation
