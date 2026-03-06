# 🔍 MikroTik Audit Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

Professional automated audit tool for MikroTik RouterOS with security checks, configuration collection, and detailed report generation.

Профессиональный инструмент для автоматизированного аудита MikroTik RouterOS с проверкой безопасности, сбором конфигурации и генерацией подробных отчетов.

## 📖 Documentation / Документация

**EN:** [View English documentation](docs/README_EN.md)

**RU:** [Смотреть русскую документацию](docs/README_RU.md)

## 🚀 Quick Start

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

## 📁 Project Structure

```
Mikrotik_audit/
├── src/           # Source code
├── tests/         # Tests
├── docs/          # Documentation
├── audit-reports/ # Generated reports (git-ignored)
└── ...
```

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
