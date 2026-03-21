# 🔍 MikroTik Audit Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Coverage](https://img.shields.io/badge/coverage-75%25-yellowgreen.svg)](https://github.com/cubiculus/Mikrotik_audit)
[![Tests](https://img.shields.io/badge/tests-639%20passed-brightgreen.svg)](https://github.com/cubiculus/Mikrotik_audit)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-blue.svg)](https://github.com/PyCQA/bandit)
[![GitHub Release](https://img.shields.io/github/v/release/cubiculus/Mikrotik_audit)](https://github.com/cubiculus/Mikrotik_audit/releases)

Professional automated audit tool for MikroTik RouterOS with security checks, web interface, and detailed reporting.

Профессиональный инструмент для автоматизированного аудита MikroTik RouterOS с веб-интерфейсом, проверкой безопасности и генерацией отчётов.

## 📖 Documentation / Документация

**EN:**
- [Main Documentation](docs/README_EN.md)
- [SSH Security Setup Guide](docs/SSH_SECURITY.md)
- [Web Interface Guide](docs/WEB_INTERFACE.md)

**RU:**
- [Основная документация](docs/README_RU.md)
- [Руководство по настройке SSH](docs/SSH_SECURITY_RU.md)
- [Веб-интерфейс](docs/WEB_INTERFACE_RU.md)

## ✅ Tested On

**RouterOS Version:** 7.22 (stable)
**Hardware:** hAP ax³ (C53UiG+5HPaxD2HPaxD)
**Python:** 3.13
**Last Tested:** March 2026
**Tests:** 639 passed ✅
**Coverage:** 75% 📊

### Features Verified:
- ✅ CLI аудит (3 уровня + 6 профилей)
- ✅ Веб-интерфейс (dashboard, история, сравнение)
- ✅ Проверка безопасности (57 проверок)
- ✅ Детектор конфликтов правил (8 типов)
- ✅ IoC детекция (10 индикаторов компрометации)
- ✅ Live CVE lookup (NIST NVD API)
- ✅ Офлайн-режим (RSC парсер)
- ✅ Автопатчинг (dry-run, rollback)
- ✅ Анализ контейнеров
- ✅ Wi-Fi проверки
- ✅ Все форматы отчётов (HTML, JSON, TXT, Markdown)

## 🚀 Quick Start

### ⚡ One-Line Install

**Linux/Mac:**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/cubiculus/Mikrotik_audit/main/scripts/quick_install.sh)
```

**Windows:**
```powershell
scripts\install.bat
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

# Install web interface (optional)
pip install -r requirements-web.txt
```

### 🎯 CLI Usage

```bash
# Run basic audit
python -m src.cli audit --router-ip 192.168.88.1 --ssh-user admin

# Run with profile (WiFi, security, network, etc.)
python -m src.cli audit --profile wifi --ssh-user admin

# Run with redaction (hide sensitive data)
python -m src.cli audit --redact --ssh-user admin

# Generate all report formats
python -m src.cli audit --all-formats --ssh-user admin

# Offline mode (analyze RSC file)
python -m src.cli audit --offline-file export.rsc
```

### 🌐 Web Interface

```bash
# Start web server
python -m src.cli web-server --port 5000

# Open browser
# http://127.0.0.1:5000
```

**Features:**
- 📊 Dashboard with statistics
- 📝 Audit history
- 🔍 Compare reports ("before/after")
- 📥 Export reports (HTML, JSON, TXT, MD)
- ⚡ Real-time audit progress

## 🎯 Use Cases

| Scenario | Why It Matters |
|----------|----------------|
| **Before firmware updates** | Document configuration and identify issues before upgrading |
| **Security audits** | Detect misconfigurations, vulnerabilities, IoC indicators |
| **Configuration conflicts** | Find unreachable rules, NAT bypasses, orphan marks |
| **Handing over** | Generate comprehensive documentation |
| **Forum troubleshooting** | Share sanitized reports for help |
| **Compliance** | Maintain audit trails |
| **Pre-deployment** | Verify configuration before production |

## 🔑 Features

### Security Analysis
- **57 security checks** across all RouterOS components
- **CVE vulnerability detection** with live NIST NVD API lookup
- **IoC detection** (10 indicators of compromise)
- **Wi-Fi security** (WPS, WEP, WPA1/TKIP detection)
- **Service hardening** (SSH, Winbox, API restrictions)

### Conflict Detection
- **Unreachable rules** (shadowed by catch-all)
- **NAT bypasses firewall**
- **Orphan routing marks**
- **Interface not in WAN/LAN lists**
- **Address list conflicts**
- **Missing FastTrack rules**
- **Duplicate rules**

### Audit Profiles
- `wifi` — Wi-Fi security checks
- `protocols` — SNMP, UPnP, Proxy, RoMON
- `system` — System-level checks
- `security` — Firewall and security
- `network` — Interfaces and routing
- `containers` — Container analysis

### Web Interface
- Dashboard with real-time statistics
- Audit history with SQLite storage
- Compare reports ("before/after")
- Export to all formats
- Real-time progress via SSE

### Offline Mode
- Analyze RSC files without router connection
- `/export hide-sensitive` support
- Same analyzers as online mode

### Auto-Patching
- Dry-run mode (preview changes)
- Confirmation for each change
- Automatic rollback capability
- Backup before changes

### Reports
- **HTML** — Interactive with charts
- **JSON** — Machine-readable
- **TXT** — Plain text
- **Markdown** — Forum-friendly

## 📁 Project Structure

```
Mikrotik_audit/
├── src/
│   ├── auditor.py              # Main audit orchestrator
│   ├── security_analyzer.py    # Security checks (57 rules)
│   ├── conflict_analyzer.py    # Conflict detection (8 types)
│   ├── ioc_analyzer.py         # IoC detection (10 indicators)
│   ├── patcher.py              # Auto-patching with rollback
│   ├── rsc_parser.py           # Offline RSC parser
│   ├── cve_database.py         # CVE database + NVD API
│   ├── commands.py             # Audit commands + profiles
│   ├── cli.py                  # CLI interface
│   ├── web/                    # Web interface
│   │   ├── app.py              # Flask server
│   │   ├── database.py         # SQLite models
│   │   └── templates/          # HTML templates
│   └── lab/                    # Lab tools
│       └── config_generator.py # Test config generator
├── tests/                      # 639 tests
├── docs/                       # Documentation
├── scripts/                    # Install/run scripts
├── audit-reports/              # Generated reports (git-ignored)
└── requirements*.txt           # Dependencies
```

## ⚙️ CLI Parameters

### Audit Command

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `--router-ip` | Router IP address or hostname | Yes* | - |
| `--ssh-port` | SSH port | No | 22 |
| `--ssh-user` | SSH username | Yes | - |
| `--ssh-key-file` | Path to SSH private key | No** | - |
| `--ssh-key-passphrase` | Passphrase for SSH key | No | - |
| `--audit-level` | Audit level (Basic/Standard/Comprehensive) | No | Standard |
| `--profile` | Audit profile (wifi/security/network/etc.) | No | - |
| `--output-dir` | Output directory for reports | No | ./audit-reports |
| `--skip-security` | Skip security analysis | No | False |
| `--max-workers` | Maximum parallel workers | No | 0 (auto) |
| `--redact` | Redact sensitive data | No | False |
| `--all-formats` | Generate all report formats | No | False |
| `--connect-timeout` | SSH connection timeout (seconds) | No | 30 |
| `--command-timeout` | Command timeout (seconds) | No | 120 |
| `--no-backup` | Skip system backup | No | False |
| `--no-cve-check` | Disable CVE check | No | False |
| `--offline-file` | RSC file for offline analysis | No* | - |

\* Either `--router-ip` or `--offline-file` must be provided
\** Either `MIKROTIK_PASSWORD` or `--ssh-key-file` must be provided

### Web Server Command

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--host` | Host to bind to | 127.0.0.1 |
| `--port` | Port to listen on | 5000 |
| `--debug` | Enable debug mode | False |

### Environment Variables

```bash
MIKROTIK_PASSWORD=your_password
MIKROTIK_SSH_KEY_FILE=~/.ssh/id_rsa
MIKROTIK_SSH_KEY_PASSPHRASE=key_passphrase
MIKROTIK_CONNECT_TIMEOUT=30
MIKROTIK_COMMAND_TIMEOUT=120
NVD_API_KEY=your_nist_api_key  # Optional, for higher rate limits
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_security_analyzer.py -v

# Run web tests
pytest tests/web/ -v
```

**Test Statistics:**
- Total tests: 639
- Passed: 639 ✅
- Coverage: 75%

## 📸 Screenshots

### Web Dashboard
![Web Dashboard](docs/screenshots/web_dashboard.png)

### HTML Report
![HTML Report](docs/screenshots/html_report_example.png)

### Conflict Detection
![Conflicts](docs/screenshots/conflicts_example.png)

## 🔗 Links

- [GitHub Repository](https://github.com/cubiculus/Mikrotik_audit)
- [Issues](https://github.com/cubiculus/Mikrotik_audit/issues)
- [Releases](https://github.com/cubiculus/Mikrotik_audit/releases)
- [Documentation](docs/README_RU.md)

## 📄 License

MIT License - see [LICENSE](docs/LICENSE) for details.

---

Made with ❤️ for the MikroTik community
