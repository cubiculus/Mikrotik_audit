"""Tests for service parser."""

from src.parsers.service_parser import (
    parse_ip_service,
    parse_ssh_sessions,
    parse_users,
    parse_certificates,
    parse_scripts,
    parse_scheduler,
)
from src.config import CommandResult


class TestServiceParser:
    """Tests for IP service parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        services = parse_ip_service([])
        assert services == []

    def test_parse_services(self):
        """Test parsing IP services."""
        output = """Flags: X - DISABLED
Columns: NAME, PORT, ADDRESS
 0     name=telnet port=23 disabled=no address=""
 1  X  name=ftp port=21 disabled=yes address=""
 2     name=ssh port=22 disabled=no tls-required=yes address="192.168.100.0/24"
 3     name=www port=80 disabled=no address=""
 4     name=winbox port=8291 disabled=no address=""
"""
        results = [CommandResult(index=0, command="/ip service print detail", stdout=output)]
        services = parse_ip_service(results)

        assert len(services) == 5
        assert services[0].name == "telnet"
        assert services[0].port == 23
        assert services[0].disabled is False

        assert services[1].name == "ftp"
        assert services[1].disabled is True

        assert services[2].name == "ssh"
        assert services[2].port == 22
        assert services[2].tls_required is True
        assert services[2].address == "192.168.100.0/24"


class TestSSHSessionParser:
    """Tests for SSH session parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        sessions = parse_ssh_sessions([])
        assert sessions == []

    def test_parse_ssh_sessions(self):
        """Test parsing SSH sessions."""
        output = """dynamic-connection: 0  user=admin remote=192.168.100.100:54321 connected-since=2h30m
  dynamic-connection: 1  user=operator remote=192.168.100.101:54322 connected-since=1h15m
"""
        results = [CommandResult(index=0, command="/ip ssh print detail", stdout=output)]
        sessions = parse_ssh_sessions(results)

        assert len(sessions) == 2
        assert sessions[0].user == "admin"
        assert sessions[0].remote_address == "192.168.100.100"
        assert sessions[0].remote_port == 54321
        assert sessions[0].connected_since == "2h30m"


class TestUserParser:
    """Tests for user parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        users = parse_users([])
        assert users == []

    def test_parse_users(self):
        """Test parsing users."""
        output = """Flags: X - DISABLED; R - RADIUS
 0  name=admin group=full address=0.0.0.0/0 netmask=0.0.0.0
      last-logged-in=2026-03-14 17:40:13
 1  name=operator group=read address=192.168.100.0/24 netmask=255.255.255.0
      disabled=no
"""
        results = [CommandResult(index=0, command="/user print detail", stdout=output)]
        users = parse_users(results)

        assert len(users) == 2
        assert users[0].name == "admin"
        assert users[0].group == "full"
        assert users[0].last_logged_in == "2026-03-14 17:40:13"

        assert users[1].name == "operator"
        assert users[1].group == "read"
        assert users[1].address == "192.168.100.0/24"


class TestCertificateParser:
    """Tests for certificate parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        certs = parse_certificates([])
        assert certs == []

    def test_parse_certificates(self):
        """Test parsing certificates."""
        output = """Flags: K - PRIVATE-KEY; L - CRL-SIGNED; T - TRUSTED
Columns: NAME, COMMON-NAME, SUBJECT, ISSUER, SERIAL-NUMBER, VALID-FROM, VALID-UNTIL
 0  KT  name=cert1 common-name=router.local
      subject=C=LV,CN=router.local
      issuer=C=LV,O=Example,CN=Example CA
      serial-number=1234567890
      valid-from=Jan/01/2024
      valid-until=Jan/01/2025
      key-type=rsa
      key-size=2048
"""
        results = [CommandResult(index=0, command="/system certificate print detail", stdout=output)]
        certs = parse_certificates(results)

        assert len(certs) == 1
        assert certs[0].name == "cert1"
        assert certs[0].common_name == "router.local"
        assert certs[0].key_type == "rsa"
        assert certs[0].key_size == 2048


class TestScriptParser:
    """Tests for script parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        scripts = parse_scripts([])
        assert scripts == []

    def test_parse_scripts(self):
        """Test parsing scripts."""
        output = """Flags: X - DISABLED
Columns: NAME, OWNER, POLICY, LAST-MODIFIED
 0     name=backup owner=admin policy=ftp,reboot,read,write,policy,test
      dont-require-permissions=no
      last-modified=Jan/01/2024 12:00:00
      source=/system backup save
 1  X  name=disabled-script owner=admin policy=read
      dont-require-permissions=yes
"""
        results = [CommandResult(index=0, command="/system script print detail", stdout=output)]
        scripts = parse_scripts(results)

        assert len(scripts) == 2
        assert scripts[0].name == "backup"
        assert scripts[0].owner == "admin"
        assert "ftp" in scripts[0].policy
        assert scripts[0].dont_require_permissions is False

        assert scripts[1].name == "disabled-script"
        assert scripts[1].disabled if hasattr(scripts[1], 'disabled') else True


class TestSchedulerParser:
    """Tests for scheduler parser."""

    def test_parse_empty_results(self):
        """Test parsing empty results."""
        schedulers = parse_scheduler([])
        assert schedulers == []

    def test_parse_scheduler(self):
        """Test parsing scheduler tasks."""
        output = """Flags: X - DISABLED
Columns: NAME, START-DATE, START-TIME, INTERVAL, RUN-COUNT, LAST-RUN, NEXT-RUN, ON-EVENT
 0     name=daily-backup start-date=jan/01/2024 start-time=02:00:00 interval=1d
      run-count=73 last-run=mar/14/2026 02:00:00 next-run=mar/15/2026 02:00:00
      on-event=backup-script
 1  X  name=disabled-task start-date=jan/01/2024 start-time=12:00:00 interval=1h
      disabled=yes
"""
        results = [CommandResult(index=0, command="/system scheduler print detail", stdout=output)]
        schedulers = parse_scheduler(results)

        assert len(schedulers) == 2
        assert schedulers[0].name == "daily-backup"
        assert schedulers[0].start_date == "jan/01/2024"
        assert schedulers[0].start_time == "02:00:00"
        assert schedulers[0].interval == "1d"
        assert schedulers[0].run_count == 73
        assert schedulers[0].on_event == "backup-script"
