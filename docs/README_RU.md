# 🔍 MikroTik Audit Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Профессиональный инструмент для автоматизированного аудита MikroTik RouterOS с проверкой безопасности, сбором конфигурации и генерацией подробных отчетов.

![MikroTik Audit](https://img.shields.io/badge/MikroTik-RouterOS-blue?style=flat-square&logo=mikrotik)
![GitHub last commit](https://img.shields.io/github/last-commit/cubiculus/Mikrotik_audit)

## 📖 Содержание

- [Возможности](#-возможности)
- [Требования](#-требования)
- [Быстрый старт](#-быстрый-старт)
- [Примеры использования](#-примеры-использования)
- [Уровни аудита](#-уровни-аудита)
- [Структура проекта](#-структура-проекта)
- [Параметры командной строки](#-параметры-командной-строки)
- [Тестирование](#-тестирование)
- [Безопасность](#-безопасность)
- [Отчеты](#-отчеты)
- [Устранение проблем](#-устранение-проблем)
- [Вклад](#-вклад)
- [Лицензия](#-лицензия)

---

## ✨ Возможности

- 🎯 **Многоуровневый аудит** - Basic, Standard, Comprehensive
- 🔒 **Проверка безопасности** - Автоматическое выявление уязвимостей конфигурации
- 📊 **Сбор конфигурации** - Полный сбор данных о системе, интерфейсах, маршрутах
- 📈 **Генерация отчетов** - HTML, JSON, TXT форматы с интерактивными графиками
- ⚡ **Кэширование** - Ускорение повторных запусков с SHA256
- 🔗 **Пул соединений** - Эффективное управление SSH подключениями
- 🧪 **Тестирование** - Покрытие тестами >80%
- 🚀 **CI/CD** - Автоматические тесты для каждой версии

---

## 📋 Требования

- Python 3.9+
- MikroTik RouterOS с включенным SSH
- Доступ к роутеру по сети

---

## 🚀 Быстрый старт

### 1. Установка

```bash
# Клонирование репозитория
git clone https://github.com/cubiculus/Mikrotik_audit.git
cd Mikrotik_audit

# Создание виртуального окружения
python -m venv venv

# Активация (Windows)
venv\Scripts\activate

# Активация (Linux/Mac)
source venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt
```

### 2. Настройка

```bash
# Копирование примера конфигурации
cp .env.example .env

# Редактирование .env
# MIKROTIK_IP=192.168.88.1
# MIKROTIK_PORT=22
# MIKROTIK_USER=admin
# MIKROTIK_PASSWORD=your_password_here
```

### 3. Запуск

```bash
# Базовый аудит
python mikrotik_audit.py

# Полный аудит
python mikrotik_audit.py --audit-level Comprehensive

# С указанием параметров
python mikrotik_audit.py \
    --router-ip 192.168.88.1 \
    --ssh-user admin \
    --output-dir ./reports
```

---

## 📊 Примеры использования

### Быстрая проверка

```bash
python mikrotik_audit.py --audit-level Basic
```

### Полный аудит с параметрами

```bash
python mikrotik_audit.py \
    --router-ip router.example.com \
    --ssh-user admin \
    --audit-level Comprehensive \
    --max-workers 10 \
    --output-dir ./audits/full
```

### Без проверки безопасности

```bash
python mikrotik_audit.py --skip-security
```

---

## 📁 Уровни аудита

### Basic
- Идентификация системы
- Пакеты системы
- IP адреса
- Интерфейсы

### Standard (по умолчанию)
- Все команды Basic +
- Пользователи и группы
- Правила firewall
- Правила NAT
- Конфигурация DNS
- Маршруты
- Сервисы
- Аренды DHCP
- Контейнеры

### Comprehensive
- Все команды Standard +
- Mangle firewall
- Списки адресов
- Настройки SSH
- Маршрутизация BGP/OSPF
- Системные логи
- Учёт трафика

---

## 📁 Структура проекта

```
Mikrotik_audit/
├── mikrotik_audit.py      # Главный скрипт
├── config.py              # Конфигурация и модели данных
├── ssh_handler.py         # SSH подключения с пулингом
├── security_analyzer.py   # Анализатор безопасности
├── report_generator.py    # Генератор отчетов (HTML/JSON/TXT)
├── data_parser.py         # Парсер выводов команд
├── commands.py            # Списки команд для аудита
├── models.py              # Модели данных
├── parsers/               # Парсеры для разных типов данных
│   ├── interface_parser.py
│   ├── ip_parser.py
│   ├── dhcp_parser.py
│   ├── container_parser.py
│   ├── firewall_parser.py
│   └── routing_parser.py
├── tests/                 # Тесты
│   ├── test_config.py
│   ├── test_ssh_handler.py
│   ├── test_security_analyzer.py
│   └── test_cache.py
├── .github/               # GitHub configuration
│   ├── workflows/
│   │   └── ci.yml
│   ├── ISSUE_TEMPLATE.md
│   └── PULL_REQUEST_TEMPLATE.md
├── .env.example           # Пример конфигурации
├── requirements.txt       # Зависимости Python
├── pytest.ini             # Конфигурация тестов
├── mypy.ini               # Конфигурация типов
├── LICENSE                # Лицензия MIT
├── README.md              # Главная документация (EN/RU)
├── README_RU.md           # Полная русская документация
└── CONTRIBUTING.md        # Руководство по внесению вклада
```

---

## 🎯 Параметры командной строки

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--router-ip` | IP адрес или hostname роутера | 192.168.1.1 |
| `--ssh-port` | SSH порт | 22 |
| `--ssh-user` | SSH пользователь | admin |
| `--ssh-pass` | SSH пароль (или через MIKROTIK_PASSWORD) | - |
| `--audit-level` | Уровень аудита: Basic, Standard, Comprehensive | Standard |
| `--output-dir` | Директория для отчетов | Mikrotik_audit-{timestamp} |
| `--skip-security` | Пропустить анализ безопасности | False |
| `--max-workers` | Максимум параллельных потоков | 5 |

---

## 🧪 Тестирование

```bash
# Запуск всех тестов
pytest

# С покрытием кода
pytest --cov=. --cov-report=html

# Конкретный файл тестов
pytest test_config.py -v

# Проверка типов
mypy mikrotik_audit.py config.py ssh_handler.py
```

---

## 🔒 Безопасность

### ⚠️ Важно

- **Никогда не коммитьте `.env`** в git
- **Используйте SSH ключи** вместо паролей при возможности
- **Храните отчеты** в защищенном месте

### Проверки безопасности

Инструмент автоматически проверяет:
- ✅ Дефолтный пользователь admin
- ✅ Пустые firewall правила
- ✅ Широкие NAT правила
- ✅ Отключенный SSH
- ✅ И другие уязвимости

---

## 📈 Отчеты

Инструмент генерирует 3 формата отчетов:

### HTML отчет
- Интерактивные графики Plotly
- Статистика выполнения
- Таблицы результатов
- Рекомендации по безопасности

### JSON отчет
- Структурированные данные
- Для дальнейшей обработки
- Интеграция с другими системами

### TXT отчет
- Текстовый формат
- Для быстрого просмотра
- Логирование

---

## 🛠️ Устранение проблем

### Ошибка подключения

```
SSHConnectionError: Connection failed
```

**Решение:**
- Проверьте доступность роутера (`ping 192.168.88.1`)
- Убедитесь, что SSH включен в RouterOS
- Проверьте логин/пароль

### Ошибка таймаута

```
SSHConnectionError: Could not get connection from pool
```

**Решение:**
- Увеличьте `connect_timeout` в config.py
- Проверьте сетевое соединение
- Уменьшите `max-workers`

---

## 🤝 Вклад

Мы приветствуем вклад в проект! Пожалуйста, ознакомьтесь с [CONTRIBUTING.md](CONTRIBUTING.md) перед началом работы.

### Основные способы внести вклад

1. 🐛 Сообщить об ошибке
2. 💡 Предложить улучшение
3. 📝 Добавить документацию
4. 🧪 Написать тесты
5. 💻 Добавить новый функционал

---

## 📄 Лицензия

Этот проект распространяется под лицензией MIT - см. файл [LICENSE](LICENSE) для деталей.

---

## 🙏 Благодарности

- MikroTik за отличные роутеры
- Всем контрибьюторам проекта
- Сообществу Python

---

## 📧 Контакты

- Проблемы: [GitHub Issues](https://github.com/cubiculus/Mikrotik_audit/issues)
- Обсуждения: [GitHub Discussions](https://github.com/cubiculus/Mikrotik_audit/discussions)
- Безопасность: [SECURITY.md](SECURITY.md)

---

## 📊 Статистика

![GitHub stars](https://img.shields.io/github/stars/cubiculus/Mikrotik_audit?style=social)
![GitHub forks](https://img.shields.io/github/forks/cubiculus/Mikrotik_audit?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/cubiculus/Mikrotik_audit?style=social)

---

Made with ❤️ for the MikroTik community
