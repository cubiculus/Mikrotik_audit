# 🧪 Testing Guide

## Overview

This guide explains how to run tests for the MikroTik Audit Tool and how to test with real RouterOS hardware.

## Running Tests

### Basic Tests (No Router Required)

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_ssh_handler.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### Integration Tests (Router Required)

Integration tests require a real RouterOS device:

```bash
# Set environment variables
export MIKROTIK_PASSWORD="your_password"
export MIKROTIK_IP="192.168.88.1"
export MIKROTIK_USER="admin"

# Run integration tests
pytest tests/test_integration/ -v -m integration
```

## Test Categories

### Unit Tests
- Test individual functions and classes
- Use mock objects
- **No router required**
- Fast execution (< 1 second per test)

### Integration Tests
- Test with real RouterOS device
- Use actual SSH connections
- **Router required** (marked with `@pytest.mark.integration`)
- Slower execution (depends on network)

## RouterOS Version Compatibility

Tests use static data that may become outdated when RouterOS changes output format.

### Known RouterOS v7 Changes:

| Command | Old Format | New Format (v7.22+) |
|---------|------------|---------------------|
| `/log print count=50` | Works | ❌ Error: `expected end of command` |
| `/ip ssh print detail` | Works | ❌ Error: `expected end of command` |
| `/container print detail` | 3-space indent | 4-space indent |

### Updating Test Data:

1. Connect to RouterOS:
   ```bash
   ssh admin@192.168.88.1
   ```

2. Run command and capture output:
   ```
   /container print detail
   ```

3. Update test fixture in `tests/test_parsers/test_container_parser.py`:
   ```python
   def test_parse_routeros_v7_containers():
       """Test parsing RouterOS v7.22+ container output."""
       output = """Flags: R - RUNNING
    0  R  name='adguardhome:latest'"""
       # ... rest of test
   ```

## SSH Error Detection

The SSH handler detects RouterOS errors even when exit_status=0:

```python
# RouterOS v7 returns exit_status=0 for invalid commands
# But stdout contains error message:
# "expected end of command (line 1 column 17)"

exit_status, stdout, stderr = ssh.execute_command("/invalid command")

# New behavior: exit_status=1 if error detected in stdout
assert exit_status == 1
assert "RouterOS error:" in stderr
```

### Detected Error Patterns:

- `expected end of command`
- `bad command name`
- `no such item`
- `failure:`
- `can not do that`
- `not enough permissions`
- `syntax error`

## Writing Tests for New Commands

When adding new commands to `src/commands.py`:

1. **Add unit test** (no router):
   ```python
   def test_new_command_parsing():
       """Test parsing new command output."""
       output = """ 0  R  name='test'"""
       result = parse_function(output)
       assert result.name == "test"
   ```

2. **Add integration test** (router required):
   ```python
   @pytest.mark.integration
   def test_new_command_on_router():
       """Test new command on real RouterOS."""
       result = ssh.execute_command("/new command")
       assert result[0] == 0
       assert "expected end of command" not in result[1]
   ```

3. **Update documentation**:
   - Add command to `src/commands.py`
   - Add test to `tests/test_parsers/`
   - Update `docs/README_*.md`

## Debugging Failed Tests

### Test passes but command fails on router:

**Problem:** Test uses outdated static data.

**Solution:** Update test data with real RouterOS output:
```python
# OLD (outdated)
output = """ 0  R  name='test'"""

# NEW (from RouterOS v7.22)
output = """Flags: R - RUNNING
 0  R  name='test'"""
```

### Command returns exit_status=0 but fails:

**Problem:** RouterOS v7 returns exit_status=0 for invalid commands.

**Solution:** SSH handler now detects errors in stdout:
```python
# Before: exit_status=0 (false success)
# After: exit_status=1 (correct failure)
exit_status, stdout, stderr = ssh.execute_command("/invalid")
assert exit_status == 1  # Now correctly detected
```

## Continuous Integration

CI runs all tests on every commit:
- Unit tests (no router)
- Code style (ruff, mypy)
- Security (bandit, detect-secrets)

Integration tests run manually or on release tags.

## Test Coverage

Target: >80% code coverage

```bash
# Check coverage
pytest tests/ --cov=src --cov-report=term-missing

# View HTML report
open htmlcov/index.html  # Mac/Linux
start htmlcov/index.html  # Windows
```

## Contributing Tests

1. Create test file: `tests/test_your_feature.py`
2. Add unit tests (required)
3. Add integration tests (optional, mark with `@pytest.mark.integration`)
4. Run tests: `pytest tests/test_your_feature.py -v`
5. Submit PR with tests passing

## Questions?

- See `tests/` directory for examples
- Check `CONTRIBUTING.md` for guidelines
- Open issue for help
