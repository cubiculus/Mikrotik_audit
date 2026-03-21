# 🌐 Web Interface Guide

## Quick Start

### Start Web Server

```bash
# Install web dependencies (first time only)
pip install -r requirements-web.txt

# Start server
python -m src.cli web-server --port 5000

# Or with custom host
python -m src.cli web-server --host 0.0.0.0 --port 8080
```

### Access Interface

Open browser: **http://127.0.0.1:5000**

---

## Features

### 📊 Dashboard

- **Statistics cards** — Total audits, completed, average score, recent activity
- **Score history chart** — Visual representation of security score over time
- **Recent audits table** — Quick access to latest audits
- **Quick actions** — Start new audit, compare reports

### 🚀 New Audit

1. Click **"Новый аудит"** in sidebar
2. Fill in connection details:
   - Router IP (required)
   - SSH port (default: 22)
   - Username (default: admin)
   - Password
3. Select audit level:
   - **Basic** — Quick audit (~10 commands)
   - **Standard** — Recommended (~100 commands)
   - **Comprehensive** — Full audit (~200 commands)
4. Optional: Select profile
   - **WiFi** — Wireless security checks
   - **Protocols** — SNMP, UPnP, Proxy, RoMON
   - **System** — System-level checks
   - **Security** — Firewall and security
   - **Network** — Interfaces and routing
   - **Containers** — Container analysis
5. Options:
   - CVE check (enabled by default)
   - Live CVE lookup (NIST NVD API)
   - Redact sensitive data
6. Click **"Запустить аудит"**
7. Watch real-time progress
8. View report when complete

### 📝 Report View

- **Security score** — Large circular indicator with color coding
- **Router info** — IP, identity, version, audit details
- **Issues by severity** — Critical, High, Medium, Low counts
- **Detailed issues list** — Expandable accordion with:
  - Finding description
  - Category
  - Recommendation
  - Fix commands

### 📜 History

- **Full audit list** — All audits with details
- **Filter and search** — Find specific audits
- **Actions**:
  - View report
  - View details
  - Delete audit

### 🔄 Compare

1. Select two audits from dropdown
2. Click **"Сравнить"**
3. View comparison:
   - Score difference
   - New issues (red)
   - Resolved issues (green)
   - Changed firewall rules

---

## API Reference

### Audits

```http
POST /api/audit/run
Content-Type: application/json

{
  "router_ip": "192.168.88.1",
  "ssh_port": 22,
  "ssh_user": "admin",
  "password": "secret",
  "audit_level": "Standard",
  "audit_profile": "wifi",
  "cve_check": true,
  "redact": false
}

Response:
{
  "audit_id": 1,
  "status": "queued",
  "message": "Audit started"
}
```

```http
GET /api/audit/<id>/status

Response:
{
  "id": 1,
  "status": "running|completed|failed",
  "security_score": 75,
  "issues_count": 5,
  "started_at": "2026-03-21T10:00:00",
  "completed_at": "2026-03-21T10:05:00",
  "error_message": null
}
```

```http
GET /api/audit/<id>/progress

Response (Server-Sent Events):
data: {"status": "running", "started_at": "..."}

data: {"status": "completed", "security_score": 75, ...}
```

```http
DELETE /api/audit/<id>/delete

Response:
{"success": true}
```

### Export

```http
GET /api/audit/<id>/export/html
GET /api/audit/<id>/export/json
GET /api/audit/<id>/export/txt
GET /api/audit/<id>/export/md
```

### Compare

```http
POST /api/compare
Content-Type: application/json

{
  "audit_id_1": 1,
  "audit_id_2": 2
}

Response:
{
  "audit1": {...},
  "audit2": {...},
  "score_difference": 5,
  "new_issues_count": 2,
  "resolved_issues_count": 1,
  "new_issues": [...],
  "resolved_issues": [...]
}
```

### Statistics

```http
GET /api/stats

Response:
{
  "total": 10,
  "completed": 8,
  "average_score": 72.5,
  "recent": 3
}
```

```http
GET /api/score-history?limit=20

Response:
[
  {"started_at": "...", "security_score": 75, "router_identity": "Router"},
  ...
]
```

---

## Database

### Location

`data/audit.db` (SQLite)

### Schema

```sql
CREATE TABLE audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_ip TEXT NOT NULL,
    router_identity TEXT,
    router_version TEXT,
    audit_level TEXT,
    audit_profile TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT,  -- pending, running, completed, failed
    security_score INTEGER,
    issues_count INTEGER,
    report_path TEXT,
    error_message TEXT
);

CREATE TABLE issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER,
    severity TEXT,
    category TEXT,
    finding TEXT,
    description TEXT,
    recommendation TEXT,
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);
```

---

## Configuration

### Environment Variables

```bash
# Web server
FLASK_ENV=development  # development|production
FLASK_DEBUG=1  # Enable debug mode

# Database
DATABASE_PATH=data/audit.db

# Optional: NVD API key for higher rate limits
NVD_API_KEY=your_api_key
```

### Server Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | 127.0.0.1 | Host to bind |
| `--port` | 5000 | Port to listen |
| `--debug` | False | Debug mode |

---

## Security

### No Authentication

By default, the web interface has **no authentication** and is intended for **local access only**.

For production use:
1. Bind to localhost only (`--host 127.0.0.1`)
2. Use reverse proxy with authentication (nginx + auth)
3. Or implement custom authentication

### Data Storage

- Passwords are **not stored** in database
- Reports are stored in `data/audits/`
- Database contains only metadata and issues

### Recommendations

1. **Development**: `python -m src.cli web-server --debug`
2. **Production**: Use behind nginx with SSL
3. **Never** expose directly to internet without authentication

---

## Troubleshooting

### Server won't start

```bash
# Check if port is in use
netstat -an | findstr :5000  # Windows
lsof -i :5000  # Linux/Mac

# Use different port
python -m src.cli web-server --port 8080
```

### Database errors

```bash
# Delete and recreate database
rm data/audit.db
python -m src.cli web-server  # Will recreate
```

### Audit stuck in "running"

- Check router connectivity
- Check logs for errors
- Restart server (audit will remain in database)

---

## Screenshots

### Dashboard
![Dashboard](screenshots/web_dashboard.png)

### New Audit
![New Audit](screenshots/web_new_audit.png)

### Report
![Report](screenshots/web_report.png)

### Compare
![Compare](screenshots/web_compare.png)

---

## Development

### Run tests

```bash
pytest tests/web/ -v
```

### Add new endpoint

```python
@app.route('/api/custom')
def api_custom():
    return jsonify({'custom': 'data'})
```

### Add new template

1. Create `src/web/templates/custom.html`
2. Extend base template:
   ```html
   {% extends "base.html" %}
   {% block content %}...{% endblock %}
   ```

---

Made with ❤️ using Flask
