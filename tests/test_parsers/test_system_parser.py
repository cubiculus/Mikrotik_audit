"""Tests for system parser."""

from src.parsers.system_parser import (
    parse_system_resource,
    parse_system_health,
    parse_system_package,
    parse_system_package_update,
)
from src.config import CommandResult


class TestSystemResourceParser:
    """Tests for system resource parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        resource = parse_system_resource([])
        assert resource.uptime == ""
        assert resource.version == ""

    def test_parse_system_resource(self):
        """Test parsing system resource information."""
        output = """uptime: 5d12h30m
  version: 7.22 (stable)
  build-time: Dec/12/2025 10:30:00
  board-name: hAP ax^3
  architecture: arm64
  cpu-count: 4
  cpu-load: 5%,12%,8%,15%
  free-memory: 524288KiB
  total-memory: 1073741824
  free-hdd: 107374182
  total-hdd: 536870912
  write-sectors-since-reboot: 123456
  bad-blocks: 0
  bad-blocks-percent: 0%
  factory-firmware: 7.12
  current-firmware: 7.22
  upgrade-firmware:
  platform: hAP ax^3
  serial-number: ABCD1234
"""
        results = [CommandResult(index=0, command="/system resource print", stdout=output)]
        resource = parse_system_resource(results)

        assert resource.uptime == "5d12h30m"
        assert resource.version == "7.22 (stable)"
        assert resource.board_name == "hAP ax^3"
        assert resource.architecture == "arm64"
        assert resource.cpu_count == 4
        assert resource.cpu_load == [5, 12, 8, 15]
        assert resource.free_memory > 0
        assert resource.total_memory > 0
        assert resource.bad_blocks == 0
        assert resource.factory_firmware == "7.12"
        assert resource.current_firmware == "7.22"

    def test_parse_cpu_load_single_core(self):
        """Test parsing CPU load for single core system."""
        output = """cpu-load: 25%
"""
        results = [CommandResult(index=0, command="/system resource print", stdout=output)]
        resource = parse_system_resource(results)

        assert resource.cpu_load == [25]

    def test_parse_memory_with_different_units(self):
        """Test parsing memory with different units."""
        output = """free-memory: 512MiB
  total-memory: 1GiB
  free-hdd: 100GiB
  total-hdd: 500GiB
"""
        results = [CommandResult(index=0, command="/system resource print", stdout=output)]
        resource = parse_system_resource(results)

        assert resource.free_memory == 512 * 1024 * 1024
        assert resource.total_memory == 1024 * 1024 * 1024


class TestSystemHealthParser:
    """Tests for system health parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        health = parse_system_health([])
        assert health.temperature == ""
        assert health.voltage == ""

    def test_parse_system_health(self):
        """Test parsing system health information."""
        output = """temperature: 45C
  voltage: 12V
  current: 0.5A
  psu1-state: ok
  psu2-state: unknown
  fan1-speed: 2500RPM
  poe-out-state: powered-on
  poe-out-current: 150mA
  board-temperature1: 42C
  junction-temperature: 50C
"""
        results = [CommandResult(index=0, command="/system health print", stdout=output)]
        health = parse_system_health(results)

        assert health.temperature == "45C"
        assert health.voltage == "12V"
        assert health.psu1_state == "ok"
        assert health.psu2_state == "unknown"
        assert health.fan1_speed == "2500RPM"
        assert health.poe_out_state == "powered-on"
        assert health.board_temperature1 == "42C"
        assert health.junction_temperature == "50C"


class TestSystemPackageParser:
    """Tests for system package parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        packages = parse_system_package([])
        assert packages == []

    def test_parse_system_packages(self):
        """Test parsing system packages."""
        output = """Flags: X - DISABLED; S - SCHEDULED
Columns: NAME, VERSION, SCHEDULED
 0  name=system version=7.22 build-time=Dec/12/2025 10:30:00 scheduled=no
 1  name=routerboard version=7.22 build-time=Dec/12/2025 10:30:00 scheduled=no
 2  name=wireless version=7.22 build-time=Dec/12/2025 10:30:00 scheduled=no disabled=yes
"""
        results = [CommandResult(index=0, command="/system package print", stdout=output)]
        packages = parse_system_package(results)

        assert len(packages) == 3
        assert packages[0]['name'] == 'system'
        assert packages[0]['version'] == '7.22'


class TestSystemPackageUpdateParser:
    """Tests for system package update parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        update = parse_system_package_update([])
        assert update['installed_version'] == ""
        assert update['update_available'] is False

    def test_parse_update_available(self):
        """Test parsing when update is available."""
        output = """installed-version: 7.21
  latest-version: 7.22
  channel: stable
  scheduled: no
"""
        results = [CommandResult(index=0, command="/system package update print", stdout=output)]
        update = parse_system_package_update(results)

        assert update['installed_version'] == "7.21"
        assert update['latest_version'] == "7.22"
        assert update['update_available'] is True
        assert update['channel'] == "stable"

    def test_parse_no_update_available(self):
        """Test parsing when no update is available."""
        output = """installed-version: 7.22
  latest-version: 7.22
  channel: stable
  scheduled: no
"""
        results = [CommandResult(index=0, command="/system package update print", stdout=output)]
        update = parse_system_package_update(results)

        assert update['installed_version'] == "7.22"
        assert update['latest_version'] == "7.22"
        assert update['update_available'] is False

    def test_parse_update_scheduled(self):
        """Test parsing when update is scheduled."""
        output = """installed-version: 7.21
  latest-version: 7.22
  channel: stable
  scheduled: yes
"""
        results = [CommandResult(index=0, command="/system package update print", stdout=output)]
        update = parse_system_package_update(results)

        assert update['scheduled'] is True
