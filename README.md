# 🔍 MikroTik Audit Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Coverage](https://codecov.io/gh/cubiculus/Mikrotik_audit/graph/badge.svg)](https://codecov.io/gh/cubiculus/Mikrotik_audit)
[![CI](https://github.com/cubiculus/Mikrotik_audit/actions/workflows/ci.yml/badge.svg)](https://github.com/cubiculus/Mikrotik_audit/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/cubiculus/Mikrotik_audit)](https://github.com/cubiculus/Mikrotik_audit/releases)
[![Issues](https://img.shields.io/github/issues/cubiculus/Mikrotik_audit)](https://github.com/cubiculus/Mikrotik_audit/issues)
[![Contributors](https://img.shields.io/github/contributors/cubiculus/Mikrotik_audit)](https://github.com/cubiculus/Mikrotik_audit/graphs/contributors)

Professional automated audit tool for MikroTik RouterOS with security checks, configuration collection, and detailed report generation.

Профессиональный инструмент для автоматизированного аудита MikroTik RouterOS с проверкой безопасности, сбором конфигурации и генерацией подробных отчетов.

## 📖 Documentation / Документация

**EN:** [View English documentation](docs/README_EN.md)

**RU:** [Смотреть русскую документацию](docs/README_RU.md)

## 🚀 Quick Start

### ⚡ One-Line Install

**Windows:**
```powershell
scripts\install.bat
```

**Linux/Mac:**
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

# Run audit with password
python -m src.cli --ssh-user admin --ssh-pass your_password

# Run audit with SSH key
python -m src.cli --ssh-user admin --ssh-key-file ~/.ssh/id_rsa

# Run audit with redaction (hide sensitive data)
python -m src.cli --ssh-user admin --ssh-pass your_password --redact
```

### 🎯 Quick Run

**Windows:**
```powershell
scripts\run_audit.bat --ssh-user admin --ssh-pass your_password
```

**Linux/Mac:**
```bash
./scripts/run_audit.sh --ssh-user admin --ssh-pass your_password
```

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
| `--ssh-pass` | SSH password | Yes* | - |
| `--ssh-key-file` | Path to SSH private key file | No* | - |
| `--ssh-key-passphrase` | Passphrase for SSH key | No | - |
| `--audit-level` | Audit detail level (Basic/Standard/Comprehensive) | No | Standard |
| `--output-dir` | Output directory for reports | No | ./audit-reports |
| `--skip-security` | Skip security analysis | No | False |
| `--max-workers` | Maximum parallel workers | No | 5 |
| `--redact` | Redact sensitive data from reports | No | False |

\* Either `--ssh-pass` or `--ssh-key-file` must be provided.

**Environment Variables:**
- `MIKROTIK_PASSWORD` - SSH password
- `MIKROTIK_SSH_KEY_FILE` - SSH key file path
- `MIKROTIK_SSH_KEY_PASSPHRASE` - SSH key passphrase

## 🔑 Features

- **Security Analysis** — automatic detection of security issues
- **Multiple Report Formats** — HTML, JSON, TXT, Markdown
- **SSH Key Authentication** — support for private key authentication
- **Sensitive Data Redaction** — mask passwords, serial numbers, IP addresses
- **Connection Pooling** — efficient SSH connection management
- **Parallel Execution** — optimized audit speed

## 📄 License

MIT License - see [LICENSE](docs/LICENSE) for details.

---

Made with ❤️ for the MikroTik community
