# 🔍 MikroTik Audit Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Professional automated audit tool for MikroTik RouterOS with security checks, configuration collection, and detailed report generation.

![MikroTik Audit](https://img.shields.io/badge/MikroTik-RouterOS-blue?style=flat-square&logo=mikrotik)
![GitHub last commit](https://img.shields.io/github/last-commit/cubiculus/Mikrotik_audit)

## 📖 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Audit Levels](#-audit-levels)
- [Project Structure](#-project-structure)
- [CLI Parameters](#-cli-parameters)
- [Testing](#-testing)
- [Security](#-security)
- [Reports](#-reports)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

- 🎯 **Multi-level audit** - Basic, Standard, Comprehensive
- 🔒 **Security checks** - Automatic detection of configuration vulnerabilities
- 📊 **Configuration collection** - Complete system, interface, and route data
- 📈 **Report generation** - HTML, JSON, TXT formats with interactive charts
- ⚡ **Caching** - SHA256-based acceleration for repeated runs
- 🔗 **Connection pooling** - Efficient SSH connection management
- 🧪 **Testing** - >80% test coverage
- 🚀 **CI/CD** - Automated tests for every version

---

## 📋 Requirements

- Python 3.9+
- MikroTik RouterOS with SSH enabled
- Network access to the router

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/cubiculus/Mikrotik_audit.git
cd Mikrotik_audit

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

```bash
# Copy config example
cp .env.example .env

# Edit .env
# MIKROTIK_IP=192.168.88.1
# MIKROTIK_PORT=22
# MIKROTIK_USER=admin
# MIKROTIK_PASSWORD=your_password_here
```

### 3. Run

```bash
# Basic audit
python mikrotik_audit.py

# Full audit
python mikrotik_audit.py --audit-level Comprehensive

# With parameters
python mikrotik_audit.py \
    --router-ip 192.168.88.1 \
    --ssh-user admin \
    --output-dir ./reports
```

---

## 📊 Usage Examples

### Quick check

```bash
python mikrotik_audit.py --audit-level Basic
```

### Full audit with parameters

```bash
python mikrotik_audit.py \
    --router-ip router.example.com \
    --ssh-user admin \
    --audit-level Comprehensive \
    --max-workers 10 \
    --output-dir ./audits/full
```

### Skip security check

```bash
python mikrotik_audit.py --skip-security
```

---

## 📁 Audit Levels

### Basic
- System identity
- System package
- IP addresses
- Interfaces

### Standard (default)
- All Basic commands +
- Users & groups
- Firewall rules
- NAT rules
- DNS config
- Routes
- Services
- DHCP leases
- Containers

### Comprehensive
- All Standard commands +
- Firewall mangle
- Address lists
- SSH settings
- BGP/OSPF routing
- System logs
- Traffic accounting

---

## 📁 Project Structure

```
Mikrotik_audit/
├── mikrotik_audit.py      # Main script
├── config.py              # Configuration & data models
├── ssh_handler.py         # SSH connections with pooling
├── security_analyzer.py   # Security analyzer
├── report_generator.py    # Report generator (HTML/JSON/TXT)
├── data_parser.py         # Command output parser
├── commands.py            # Audit command lists
├── models.py              # Data models
├── parsers/               # Parsers for different data types
│   ├── interface_parser.py
│   ├── ip_parser.py
│   ├── dhcp_parser.py
│   ├── container_parser.py
│   ├── firewall_parser.py
│   └── routing_parser.py
├── tests/                 # Tests
│   ├── test_config.py
│   ├── test_ssh_handler.py
│   ├── test_security_analyzer.py
│   └── test_cache.py
├── .github/               # GitHub configuration
│   ├── workflows/
│   │   └── ci.yml
│   ├── ISSUE_TEMPLATE.md
│   └── PULL_REQUEST_TEMPLATE.md
├── .env.example           # Config example
├── requirements.txt       # Python dependencies
├── pytest.ini             # Pytest configuration
├── mypy.ini               # MyPy configuration
├── LICENSE                # MIT License
├── README.md              # Main documentation (EN/RU)
├── README_RU.md           # Full Russian documentation
├── README_EN.md           # Full English documentation
└── CONTRIBUTING.md        # Contributing guide
```

---

## 🎯 CLI Parameters

| Parameter | Description | Default |
|----------|----------|--------------|
| `--router-ip` | Router IP address or hostname | 192.168.1.1 |
| `--ssh-port` | SSH port | 22 |
| `--ssh-user` | SSH username | admin |
| `--ssh-pass` | SSH password (or via MIKROTIK_PASSWORD) | - |
| `--audit-level` | Audit level: Basic, Standard, Comprehensive | Standard |
| `--output-dir` | Output directory for reports | Mikrotik_audit-{timestamp} |
| `--skip-security` | Skip security analysis | False |
| `--max-workers` | Maximum parallel threads | 5 |

---

## 🧪 Testing

```bash
# Run all tests
pytest

# With code coverage
pytest --cov=. --cov-report=html

# Specific test file
pytest test_config.py -v

# Type checking
mypy mikrotik_audit.py config.py ssh_handler.py
```

---

## 🔒 Security

### ⚠️ Important

- **Never commit `.env`** to git
- **Use SSH keys** instead of passwords when possible
- **Store reports** in a secure location

### Security Checks

The tool automatically checks for:
- ✅ Default admin user
- ✅ Empty firewall rules
- ✅ Overly permissive NAT rules
- ✅ Disabled SSH
- ✅ Other vulnerabilities

---

## 📈 Reports

The tool generates 3 report formats:

### HTML Report
- Interactive Plotly charts
- Execution statistics
- Results tables
- Security recommendations

### JSON Report
- Structured data
- For further processing
- Integration with other systems

### TXT Report
- Text format
- For quick review
- Logging

---

## 🛠️ Troubleshooting

### Connection Error

```
SSHConnectionError: Connection failed
```

**Solution:**
- Check router availability (`ping 192.168.88.1`)
- Ensure SSH is enabled in RouterOS
- Verify login/password

### Timeout Error

```
SSHConnectionError: Could not get connection from pool
```

**Solution:**
- Increase `connect_timeout` in config.py
- Check network connection
- Decrease `max-workers`

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) before starting.

### Main ways to contribute

1. 🐛 Report a bug
2. 💡 Suggest an improvement
3. 📝 Add documentation
4. 🧪 Write tests
5. 💻 Add new features

---

## 📄 License

This project is distributed under the MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- MikroTik for excellent routers
- All project contributors
- Python community

---

## 📧 Contacts

- Issues: [GitHub Issues](https://github.com/cubiculus/Mikrotik_audit/issues)
- Discussions: [GitHub Discussions](https://github.com/cubiculus/Mikrotik_audit/discussions)
- Security: [SECURITY.md](SECURITY.md)

---

## 📊 Stats

![GitHub stars](https://img.shields.io/github/stars/cubiculus/Mikrotik_audit?style=social)
![GitHub forks](https://img.shields.io/github/forks/cubiculus/Mikrotik_audit?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/cubiculus/Mikrotik_audit?style=social)

---

Made with ❤️ for the MikroTik community
