# 🌐 Руководство по веб-интерфейсу

## Быстрый старт

### Запуск сервера

```bash
# Установить зависимости (первый раз)
pip install -r requirements-web.txt

# Запустить сервер
python -m src.cli web-server --port 5000

# Или с другими параметрами
python -m src.cli web-server --host 0.0.0.0 --port 8080
```

### Доступ к интерфейсу

Откройте браузер: **http://127.0.0.1:5000**

---

## Возможности

### 📊 Dashboard

- **Карточки статистики** — Всего аудитов, завершено, средний балл, активность
- **График истории** — Визуализация security score по времени
- **Таблица последних аудитов** — Быстрый доступ
- **Быстрые действия** — Новый аудит, сравнение отчётов

### 🚀 Новый аудит

1. Нажмите **"Новый аудит"** в боковой панели
2. Заполните данные подключения:
   - IP роутера (обязательно)
   - SSH порт (по умолчанию: 22)
   - Пользователь (по умолчанию: admin)
   - Пароль
3. Выберите уровень аудита:
   - **Basic** — Быстрый аудит (~10 команд)
   - **Standard** — Рекомендуемый (~100 команд)
   - **Comprehensive** — Полный (~200 команд)
4. Опционально: Выберите профиль
   - **WiFi** — Проверки беспроводной безопасности
   - **Протоколы** — SNMP, UPnP, Proxy, RoMON
   - **Системные** — Системные проверки
   - **Безопасность** — Фаервол и безопасность
   - **Сеть** — Интерфейсы и маршрутизация
   - **Контейнеры** — Анализ контейнеров
5. Опции:
   - CVE проверка (включено по умолчанию)
   - Live CVE lookup (NIST NVD API)
   - Скрыть чувствительные данные
6. Нажмите **"Запустить аудит"**
7. Наблюдайте за прогрессом в реальном времени
8. Просмотрите отчёт по завершении

### 📝 Просмотр отчёта

- **Security score** — Большой круговой индикатор с цветом
- **Информация о роутере** — IP, идентификатор, версия
- **Проблемы по severity** — Количество Critical, High, Medium, Low
- **Детальный список** — Раскрывающийся аккордеон:
  - Описание проблемы
  - Категория
  - Рекомендация
  - Команды для исправления

### 📜 История

- **Полный список аудитов** — Все аудиты с деталями
- **Фильтр и поиск** — Найти конкретные аудиты
- **Действия**:
  - Просмотр отчёта
  - Просмотр деталей
  - Удалить аудит

### 🔄 Сравнение

1. Выберите два аудита из dropdown
2. Нажмите **"Сравнить"**
3. Просмотр сравнения:
   - Разница в score
   - Новые проблемы (красным)
   - Исправленные проблемы (зелёным)
   - Изменённые правила фаервола

---

## API Reference

### Аудиты

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

Ответ:
{
  "audit_id": 1,
  "status": "queued",
  "message": "Аудит запущен"
}
```

```http
GET /api/audit/<id>/status

Ответ:
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

Ответ (Server-Sent Events):
data: {"status": "running", "started_at": "..."}

data: {"status": "completed", "security_score": 75, ...}
```

```http
DELETE /api/audit/<id>/delete

Ответ:
{"success": true}
```

### Экспорт

```http
GET /api/audit/<id>/export/html
GET /api/audit/<id>/export/json
GET /api/audit/<id>/export/txt
GET /api/audit/<id>/export/md
```

### Сравнение

```http
POST /api/compare
Content-Type: application/json

{
  "audit_id_1": 1,
  "audit_id_2": 2
}

Ответ:
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

### Статистика

```http
GET /api/stats

Ответ:
{
  "total": 10,
  "completed": 8,
  "average_score": 72.5,
  "recent": 3
}
```

```http
GET /api/score-history?limit=20

Ответ:
[
  {"started_at": "...", "security_score": 75, "router_identity": "Router"},
  ...
]
```

---

## База данных

### Расположение

`data/audit.db` (SQLite)

### Схема

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

## Конфигурация

### Переменные окружения

```bash
# Веб-сервер
FLASK_ENV=development  # development|production
FLASK_DEBUG=1  # Режим отладки

# База данных
DATABASE_PATH=data/audit.db

# Опционально: API ключ NVD для больших лимитов
NVD_API_KEY=your_api_key
```

### Опции сервера

| Опция | По умолчанию | Описание |
|-------|--------------|----------|
| `--host` | 127.0.0.1 | Хост для bind |
| `--port` | 5000 | Порт для listen |
| `--debug` | False | Режим отладки |

---

## Безопасность

### Без аутентификации

По умолчанию веб-интерфейс **не имеет аутентификации** и предназначен **только для локального доступа**.

Для продакшена:
1. Bind только на localhost (`--host 127.0.0.1`)
2. Используйте reverse proxy с аутентификацией (nginx + auth)
3. Или реализуйте собственную аутентификацию

### Хранение данных

- Пароли **не хранятся** в базе данных
- Отчёты хранятся в `data/audits/`
- База содержит только метаданные и проблемы

### Рекомендации

1. **Разработка**: `python -m src.cli web-server --debug`
2. **Продакшен**: Используйте за nginx с SSL
3. **Никогда** не открывайте доступ в интернет без аутентификации

---

## Troubleshooting

### Сервер не запускается

```bash
# Проверьте занятость порта
netstat -an | findstr :5000  # Windows
lsof -i :5000  # Linux/Mac

# Используйте другой порт
python -m src.cli web-server --port 8080
```

### Ошибки базы данных

```bash
# Удалите и пересоздайте базу
rm data/audit.db
python -m src.cli web-server  # Пересоздаст
```

### Аудит застрял в "running"

- Проверьте подключение к роутеру
- Проверьте логи на ошибки
- Перезапустите сервер (аудит останется в базе)

---

## Скриншоты

### Dashboard
![Dashboard](screenshots/web_dashboard.png)

### Новый аудит
![Новый аудит](screenshots/web_new_audit.png)

### Отчёт
![Отчёт](screenshots/web_report.png)

### Сравнение
![Сравнение](screenshots/web_compare.png)

---

## Разработка

### Запуск тестов

```bash
pytest tests/web/ -v
```

### Добавить endpoint

```python
@app.route('/api/custom')
def api_custom():
    return jsonify({'custom': 'data'})
```

### Добавить шаблон

1. Создайте `src/web/templates/custom.html`
2. Расширьте base шаблон:
   ```html
   {% extends "base.html" %}
   {% block content %}...{% endblock %}
   ```

---

Сделано с ❤️ на Flask
