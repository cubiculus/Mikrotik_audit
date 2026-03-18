"""Tests for command sanitization in SSH handler."""

from src.ssh_handler import _sanitize_command


class TestSanitizeCommand:
    """Tests for _sanitize_command function."""

    def test_allows_basic_commands(self):
        """Test that basic RouterOS commands are allowed."""
        cmd = "/system resource print"
        result = _sanitize_command(cmd)
        assert result == cmd

    def test_allows_spaces(self):
        """Test that spaces are preserved."""
        cmd = "/ip route print detail"
        result = _sanitize_command(cmd)
        assert result == cmd

    def test_allows_slashes_and_dashes(self):
        """Test that slashes and dashes are preserved."""
        cmd = "/interface ethernet print stats"
        result = _sanitize_command(cmd)
        assert result == cmd

    def test_allows_equals_sign(self):
        """Test that equals sign is preserved."""
        cmd = '/ip route add dst-address=192.168.1.0/24'
        result = _sanitize_command(cmd)
        assert result == cmd

    def test_allows_brackets(self):
        """Test that brackets are preserved."""
        cmd = '/ip firewall filter add chain=input dst-port=[80,443]'
        result = _sanitize_command(cmd)
        assert result == cmd

    def test_allows_comma_in_lists(self):
        """Test that commas are preserved for lists."""
        cmd = '/ip firewall filter add chain=input dst-port=[80,443,8080]'
        result = _sanitize_command(cmd)
        assert result == cmd
        assert ',' in result

    def test_allows_quotes(self):
        """Test that quotes are preserved."""
        cmd = '/log print where topics~"firewall"'
        result = _sanitize_command(cmd)
        assert result == cmd

    def test_removes_semicolon(self):
        """Test that semicolon is removed (dangerous shell metacharacter)."""
        cmd = "/system resource print; rm -rf /"
        result = _sanitize_command(cmd)
        assert ";" not in result
        assert "rm -rf" not in result

    def test_removes_pipe(self):
        """Test that pipe is removed (dangerous shell metacharacter)."""
        cmd = "/system resource print | cat"
        result = _sanitize_command(cmd)
        assert "|" not in result
        assert "cat" not in result

    def test_removes_ampersand(self):
        """Test that ampersand is removed (dangerous shell metacharacter)."""
        cmd = "/system resource print & malicious_command"
        result = _sanitize_command(cmd)
        assert "&" not in result
        assert "malicious_command" not in result

    def test_removes_dollar_sign(self):
        """Test that dollar sign is removed (variable expansion)."""
        cmd = "/system resource print $HOME"
        result = _sanitize_command(cmd)
        assert "$" not in result
        assert "HOME" not in result

    def test_removes_backtick(self):
        """Test that backtick is removed (command substitution)."""
        cmd = "/system resource print `malicious`"
        result = _sanitize_command(cmd)
        assert "`" not in result
        assert "malicious" not in result

    def test_removes_parentheses(self):
        """Test that parentheses are removed."""
        cmd = "/system resource print (malicious)"
        result = _sanitize_command(cmd)
        assert "(" not in result
        assert ")" not in result
        assert "malicious" not in result

    def test_removes_braces(self):
        """Test that curly braces are removed."""
        cmd = "/system resource print {malicious}"
        result = _sanitize_command(cmd)
        assert "{" not in result
        assert "}" not in result
        assert "malicious" not in result

    def test_removes_angle_brackets(self):
        """Test that angle brackets are removed (redirection)."""
        cmd = "/system resource print > /dev/null"
        result = _sanitize_command(cmd)
        assert ">" not in result
        assert "/dev/null" not in result

    def test_removes_backslash(self):
        """Test that backslash is removed."""
        cmd = "/system resource print\\malicious"
        result = _sanitize_command(cmd)
        assert "\\" not in result

    def test_sanitize_preserves_tilde_operator(self):
        """Test that tilde operator is preserved (regex match)."""
        cmd = '/log print where topics~"firewall"'
        result = _sanitize_command(cmd)
        assert result == cmd
        assert "~" in result

    def test_sanitize_preserves_not_equal_operator(self):
        """Test that not equal operator (!=) is preserved."""
        cmd = '/ip route print where routing-mark!=""'
        result = _sanitize_command(cmd)
        assert result == cmd
        assert "!=" in result

    def test_sanitize_preserves_negation_operator(self):
        """Test that exclamation mark (negation) is preserved."""
        cmd = '/ip firewall filter print where disabled=no'
        result = _sanitize_command(cmd)
        assert result == cmd

    def test_sanitize_preserves_exclamation_in_command(self):
        """Test that exclamation mark within command is preserved."""
        cmd = '/ip route print where interface!=""'
        result = _sanitize_command(cmd)
        assert "!" in result
        assert result == cmd

    def test_sanitize_strips_whitespace(self):
        """Test that leading/trailing whitespace is stripped."""
        cmd = "  /system resource print  "
        result = _sanitize_command(cmd)
        assert result == "/system resource print"

    def test_sanitize_handles_empty_command(self):
        """Test that empty command is handled."""
        result = _sanitize_command("   ")
        assert result == ""

    def test_sanitize_preserves_colon(self):
        """Test that colon is preserved."""
        cmd = "/system license print"
        result = _sanitize_command(cmd)
        assert result == cmd

    def test_sanitize_preserves_underscore(self):
        """Test that underscore is preserved."""
        cmd = "/tool sniffer quick file=test_file"
        result = _sanitize_command(cmd)
        assert result == cmd

    def test_sanitize_preserves_dot(self):
        """Test that dot is preserved."""
        cmd = "/system routerboard print"
        result = _sanitize_command(cmd)
        assert result == cmd
