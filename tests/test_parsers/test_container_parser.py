"""Tests for container parser."""

from src.parsers.container_parser import (
    parse_containers,
    _parse_container_param_cached,
    _set_container_field,
    CONTAINER_HEADER_PATTERN,
    NEW_CONTAINER_PATTERN,
    INDENTED_PATTERN
)
from src.config import CommandResult
from src.models import Container


class TestContainerParserHelpers:
    """Tests for helper functions in container parser."""

    def test_parse_container_param_cached_with_valid_param(self):
        """Test parsing valid container parameter."""
        key, value = _parse_container_param_cached("name='my-container'")
        assert key == "name"
        assert value == "my-container"

    def test_parse_container_param_cached_without_quotes(self):
        """Test parsing parameter without quotes."""
        key, value = _parse_container_param_cached("status=running")
        assert key == "status"
        assert value == "running"

    def test_parse_container_param_cached_invalid_format(self):
        """Test parsing parameter without equals sign."""
        key, value = _parse_container_param_cached("invalid_param")
        assert key is None
        assert value is None

    def test_parse_container_param_cached_empty_string(self):
        """Test parsing empty string."""
        key, value = _parse_container_param_cached("")
        assert key is None
        assert value is None

    def test_parse_container_param_cached_caching(self):
        """Test that parsing is cached."""
        result1 = _parse_container_param_cached("name='test'")
        result2 = _parse_container_param_cached("name='test'")
        assert result1 == result2

    def test_set_container_field_valid_field(self):
        """Test setting valid container field."""
        container = Container()
        _set_container_field(container, "name", "test-container")
        assert container.name == "test-container"

    def test_set_container_field_root_directory(self):
        """Test setting root-directory field."""
        container = Container()
        _set_container_field(container, "root-directory", "/disk1/containers")
        assert container.root_dir == "/disk1/containers"
        assert container.root_directory == "/disk1/containers"

    def test_set_container_field_invalid_field(self):
        """Test setting invalid field does nothing."""
        container = Container()
        _set_container_field(container, "invalid_field", "value")
        # Container.name has default value "" (empty string), not None
        assert container.name == ""

    def test_set_container_field_image(self):
        """Test setting remote-image field."""
        container = Container()
        _set_container_field(container, "remote-image", "nginx:latest")
        assert container.image == "nginx:latest"

    def test_set_container_field_ip_address(self):
        """Test setting ip-address field."""
        container = Container()
        _set_container_field(container, "ip-address", "172.18.0.2")
        assert container.ip_address == "172.18.0.2"


class TestContainerParserPatterns:
    """Tests for regex patterns in container parser."""

    def test_container_header_pattern_match(self):
        """Test container header pattern matching."""
        match = CONTAINER_HEADER_PATTERN.match("0  DRSI  name='test'")
        assert match is not None
        assert match.group(1) == "0"  # index
        assert match.group(2) == "DRSI"  # flags
        assert match.group(3).strip() == "name='test'"  # rest of line

    def test_container_header_pattern_running(self):
        """Test pattern with running container flags."""
        match = CONTAINER_HEADER_PATTERN.match("1  R  name='running-container'")
        assert match is not None
        assert match.group(1) == "1"  # index
        assert match.group(2) == "R"  # flags

    def test_container_header_pattern_stopped(self):
        """Test pattern with stopped container (no flags)."""
        match = CONTAINER_HEADER_PATTERN.match("0    name='stopped-container'")
        assert match is not None
        assert match.group(1) == "0"  # index
        assert match.group(2) == ""  # no flags

    def test_container_header_pattern_no_match(self):
        """Test pattern with non-container line."""
        match = CONTAINER_HEADER_PATTERN.match("  some indented line")
        assert match is None

    def test_new_container_pattern_match(self):
        """Test new container pattern."""
        match = NEW_CONTAINER_PATTERN.match("5  R  name='container'")
        assert match is not None

    def test_new_container_pattern_no_match(self):
        """Test new container pattern with indented line."""
        match = NEW_CONTAINER_PATTERN.match("   name='container'")
        assert match is None

    def test_indented_pattern_match(self):
        """Test indented pattern matching."""
        match = INDENTED_PATTERN.match("   name='value'")
        assert match is not None

    def test_indented_pattern_no_match(self):
        """Test indented pattern with non-indented line."""
        match = INDENTED_PATTERN.match("name='value'")
        assert match is None


class TestContainerParser:
    """Tests for main container parser function."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        containers, overview = parse_containers([])
        assert containers == []
        assert overview.containers_total == 0
        assert overview.containers_running == 0

    def test_parse_error_results(self):
        """Test parsing results with errors."""
        results = [
            CommandResult(
                index=0,
                command="/container print",
                stdout="",
                stderr="error",
                has_error=True
            )
        ]
        containers, overview = parse_containers(results)
        assert containers == []
        assert overview.containers_total == 0

    def test_parse_running_container(self):
        """Test parsing running container."""
        output = """Flags: R - RUNNING
 0  R  name='nginx-container' remote-image='nginx:latest' root-directory='/disk1/nginx'
      interface=veth1 ip-address=172.18.0.2 creation-time=jan/01/2024 00:00:00
      started=yes uptime=1d2h3m
"""
        results = [
            CommandResult(index=0, command="/container print", stdout=output)
        ]
        containers, overview = parse_containers(results)

        assert len(containers) == 1
        assert containers[0].name == "nginx-container"
        assert containers[0].image == "nginx:latest"
        assert containers[0].status == "running"
        assert overview.containers_running == 1
        assert overview.containers_total == 1

    def test_parse_stopped_container(self):
        """Test parsing stopped container."""
        output = """Flags:
 0    name='stopped-container' remote-image='redis:latest'
      started=no
"""
        results = [
            CommandResult(index=0, command="/container print", stdout=output)
        ]
        containers, overview = parse_containers(results)

        assert len(containers) == 1
        assert containers[0].name == "stopped-container"
        assert containers[0].status == "stopped"
        assert overview.containers_running == 0
        assert overview.containers_total == 1

    def test_parse_multiple_containers(self):
        """Test parsing multiple containers."""
        output = """Flags: R - RUNNING
 0  R  name='container1' remote-image='nginx:latest'
      started=yes
 1    name='container2' remote-image='redis:latest'
      started=no
 2  R  name='container3' remote-image='postgres:latest'
      started=yes
"""
        results = [
            CommandResult(index=0, command="/container print", stdout=output)
        ]
        containers, overview = parse_containers(results)

        assert len(containers) == 3
        assert overview.containers_total == 3
        assert overview.containers_running == 2

    def test_parse_container_with_all_fields(self):
        """Test parsing container with all fields."""
        output = """Flags: R - RUNNING
 0  R  name='full-container' remote-image='app:1.0' root-directory='/disk1/app'
      interface=veth2 ip-address=172.18.0.5 creation-time='jan/15/2024 10:30:00'
      started=yes uptime=5d10h20m
"""
        results = [
            CommandResult(index=0, command="/container print", stdout=output)
        ]
        containers, overview = parse_containers(results)

        container = containers[0]
        assert container.name == "full-container"
        assert container.image == "app:1.0"
        assert container.root_directory == "/disk1/app"
        assert container.interface == "veth2"
        assert container.ip_address == "172.18.0.5"
        assert container.status == "running"

    def test_parse_container_mixed_status(self):
        """Test parsing containers with mixed status."""
        output = """Flags: R - RUNNING
 0  R  name='running1'
 1    name='stopped1'
 2  R  name='running2'
 3    name='stopped2'
"""
        results = [
            CommandResult(index=0, command="/container print", stdout=output)
        ]
        containers, overview = parse_containers(results)

        assert len(containers) == 4
        assert overview.containers_running == 2
        assert overview.containers_total == 4

    def test_parse_container_without_name(self):
        """Test that containers without names are skipped."""
        output = """Flags: R - RUNNING
 0  R  remote-image='nginx:latest'
"""
        results = [
            CommandResult(index=0, command="/container print", stdout=output)
        ]
        containers, overview = parse_containers(results)

        assert len(containers) == 0

    def test_parse_container_compact_format(self):
        """Test parsing container in compact format."""
        output = """Flags: R - RUNNING
 0  R  name='compact' remote-image='image:tag' started=yes
"""
        results = [
            CommandResult(index=0, command="/container print", stdout=output)
        ]
        containers, overview = parse_containers(results)

        assert len(containers) == 1
        assert containers[0].name == "compact"
        assert containers[0].status == "running"
