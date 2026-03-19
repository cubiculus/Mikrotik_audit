# 🔍 MikroTik Audit Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Coverage](https://codecov.io/gh/cubiculus/Mikrotik_audit/graph/badge.svg)](https://codecov.io/gh/cubiculus/Mikrotik_audit)
[![CI](https://github.com/cubiculus/Mikrotik_audit/actions/workflows/ci.yml/badge.svg)](https://github.com/cubiculus/Mikrotik_audit/actions/workflows/ci.yml)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-blue.svg)](https://github.com/PyCQA/bandit)
[![GitHub Release](https://img.shields.io/github/v/release/cubiculus/Mikrotik_audit)](https://github.com/cubiculus/Mikrotik_audit/releases)
[![Issues](https://img.shields.io/github/issues/cubiculus/Mikrotik_audit)](https://github.com/cubiculus/Mikrotik_audit/issues)
[![Contributors](https://img.shields.io/github/contributors/cubiculus/Mikrotik_audit)](https://github.com/cubiculus/Mikrotik_audit/graphs/contributors)

Professional automated audit tool for MikroTik RouterOS with security checks, configuration collection, and detailed report generation.

Профессиональный инструмент для автоматизированного аудита MikroTik RouterOS с проверкой безопасности, сбором конфигурации и генерацией подробных отчетов.

## 📖 Documentation / Документация

**EN:**
- [Main Documentation](docs/README_EN.md)
- [SSH Security Setup Guide](docs/SSH_SECURITY.md)

**RU:**
- [Основная документация](docs/README_RU.md)
- [Руководство по настройке SSH](docs/SSH_SECURITY_RU.md)

## ✅ Tested On

**RouterOS Version:** 7.22 (stable)
**Hardware:** hAP ax³ (C53UiG+5HPaxD2HPaxD)
**Python:** 3.13
**Last Tested:** March 2026

### Features Verified:
- ✅ System backup creation and download
- ✅ Container detection and parsing (Docker)
- ✅ Security analysis (firewall, services, SSH)
- ✅ All report formats (HTML, JSON, TXT, Markdown)
- ✅ SSH key authentication
- ✅ Comprehensive audit level (148 commands)

## 🚀 Quick Start

### ⚡ One-Line Install

**Linux/Mac (recommended):**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/cubiculus/Mikrotik_audit/main/scripts/quick_install.sh)
```

**Windows:**
```powershell
scripts\install.bat
```

**Linux/Mac (alternative):**
```bash
bash scripts/install.sh
```

### 📋 Manual Install

```bash
# Clone repository
git clone https://github.com/cubiculus/Mikrotik_audit.git
cd Mikrotik_audit

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run audit with password (using environment variable)
set MIKROTIK_PASSWORD=your_password && python -m src.cli --ssh-user admin

# Run audit with SSH key
python -m src.cli --ssh-user admin --ssh-key-file ~/.ssh/id_rsa

# Run audit with redaction (hide sensitive data)
set MIKROTIK_PASSWORD=your_password && python -m src.cli --ssh-user admin --redact

# Generate all report formats (html, json, txt, md)
set MIKROTIK_PASSWORD=your_password && python -m src.cli --ssh-user admin --all-formats
```

### 🎯 Quick Run

**Windows:**
```powershell
# First time setup: Add router's SSH key to known_hosts
ssh-keyscan -H 192.168.1.1 | Add-Content $env:USERPROFILE\.ssh\known_hosts

# Run audit
scripts\run_audit.bat --ssh-user admin
```

**Linux/Mac:**
```bash
# First time setup: Add router's SSH key to known_hosts
ssh-keyscan -H 192.168.1.1 >> ~/.ssh/known_hosts

# Run audit
./scripts/run_audit.sh --ssh-user admin
```

> **Note:** Set `MIKROTIK_PASSWORD` environment variable before running, or use SSH key authentication.
>
> 🔒 **Security:** The tool uses `RejectPolicy()` which requires the router's SSH key to be pre-added to `known_hosts` for protection against MITM attacks.

## 📸 Screenshots

### HTML Report Example

![HTML Report Example](docs/screenshots/html_report_example.png)

*Example HTML report showing security issues and configuration summary*

### Markdown Report Example

![Markdown Report Example](docs/screenshots/markdown_report_example.png)

*Markdown report suitable for forums and documentation*

> 📝 **Note:** Screenshots are for illustration. Actual report content depends on your router configuration.

## 🎯 Use Cases

This tool is essential for:

| Scenario | Why It Matters |
|----------|----------------|
| **Before firmware updates** | Document current configuration state and identify potential issues before upgrading RouterOS |
| **Handing over to another specialist** | Generate comprehensive documentation for the next administrator |
| **Forum troubleshooting** | Share sanitized (redacted) configuration reports when asking for help on MikroTik forums |
| **Security audits** | Automatically detect misconfigurations, weak passwords, and security vulnerabilities |
| **Compliance documentation** | Maintain audit trails for network compliance requirements |
| **Pre-deployment verification** | Verify router configuration before putting into production |

## 📁 Project Structure

```
Mikrotik_audit/
├── src/           # Source code
├── tests/         # Tests
├── docs/          # Documentation
├── audit-reports/ # Generated reports (git-ignored)
└── ...
```

## ⚙️ CLI Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `--router-ip` | Router IP address or hostname | Yes | Auto-detect |
| `--ssh-port` | SSH port | No | 22 |
| `--ssh-user` | SSH username | Yes | - |
| `--ssh-key-file` | Path to SSH private key file | No* | - |
| `--ssh-key-passphrase` | Passphrase for SSH key | No | - |
| `--audit-level` | Audit detail level (Basic/Standard/Comprehensive) | No | Standard |
| `--output-dir` | Output directory for reports | No | ./audit-reports |
| `--skip-security` | Skip security analysis | No | False |
| `--max-workers` | Maximum parallel workers | No | 0 (auto) |
| `--redact` | Redact sensitive data from reports | No | False |
| `--all-formats` | Generate all report formats (html,json,txt,md) | No | False |
| `--connect-timeout` | SSH connection timeout in seconds | No | 30 |
| `--command-timeout` | Command execution timeout in seconds | No | 120 |
| `--no-backup` | Skip system backup | No | False |
| `--verbose` | Enable verbose logging (DEBUG level) | No | False |
| `--quiet` | Suppress non-essential output | No | False |
| `--no-cve-check` | Disable CVE check for RouterOS version | No | False |

\* Either `MIKROTIK_PASSWORD` environment variable or `--ssh-key-file` must be provided.

**Environment Variables:**
- `MIKROTIK_PASSWORD` - SSH password
- `MIKROTIK_SSH_KEY_FILE` - SSH key file path
- `MIKROTIK_SSH_KEY_PASSPHRASE` - SSH key passphrase
- `MIKROTIK_CONNECT_TIMEOUT` - SSH connection timeout (seconds)
- `MIKROTIK_COMMAND_TIMEOUT` - Command execution timeout (seconds)

## 🔑 Features

- **Security Analysis** — automatic detection of security issues
- **CVE Vulnerability Check** — check RouterOS version against known CVE database (CVE-2018-14847, CVE-2021-42069, etc.)
- **Multiple Report Formats** — HTML, JSON, TXT, Markdown
- **SSH Key Authentication** — support for private key authentication
- **Sensitive Data Redaction** — mask passwords, serial numbers, IP addresses
- **Connection Pooling** — efficient SSH connection management
- **Parallel Execution** — optimized audit speed
- **Security Hardening** — Bandit security checks, sanitized commands, safe serialization (JSON)

## 📄 License

MIT License - see [LICENSE](docs/LICENSE) for details.

---

Made with ❤️ for the MikroTik community
