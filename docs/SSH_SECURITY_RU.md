# 🔐 Руководство по настройке SSH безопасности

## Политика безопасности

Этот инструмент использует **`RejectPolicy()`** для проверки SSH ключей хостов. Это самая безопасная политика, защищающая от атак типа Man-in-the-Middle (MITM).

### Почему RejectPolicy()?

| Политика | Поведение | Уровень безопасности |
|----------|-----------|----------------------|
| **`RejectPolicy()`** | Отклоняет неизвестные хосты | 🔒 **Максимальный** |
| `WarningPolicy()` | Предупреждает, но подключается | ⚠️ Средний |
| `AutoAddPolicy()` | Автоматически добавляет в known_hosts | ⚠️ Низкий |

**RejectPolicy()** требует предварительного добавления публичного SSH ключа роутера в файл `known_hosts` перед подключением.

---

## 🚀 Первоначальная настройка

### Шаг 1: Добавление SSH ключа роутера

**Windows PowerShell:**
```powershell
ssh-keyscan -H 192.168.1.1 | Add-Content $env:USERPROFILE\.ssh\known_hosts
```

**Linux/Mac:**
```bash
ssh-keyscan -H 192.168.1.1 >> ~/.ssh/known_hosts
```

Замените `192.168.1.1` на IP адрес вашего роутера.

### Шаг 2: Проверка добавления ключа

**Windows:**
```powershell
Get-Content $env:USERPROFILE\.ssh\known_hosts | Select-String "192.168.1.1"
```

**Linux/Mac:**
```bash
grep "192.168.1.1" ~/.ssh/known_hosts
```

Вы должны увидеть что-то вроде:
```
192.168.1.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...
```

### Шаг 3: Запуск аудита

```bash
# Установка пароля
$env:MIKROTIK_PASSWORD="your_password"  # PowerShell
export MIKROTIK_PASSWORD="your_password"  # Linux/Mac

# Запуск аудита
python -m src.cli --ssh-user admin --router-ip 192.168.1.1
```

---

## 🔑 Альтернатива: Аутентификация по SSH ключу

Вместо пароля можно использовать SSH ключи для лучшей безопасности.

### Генерация SSH ключа

```bash
ssh-keygen -t ed25519 -C "mikrotik-audit"
```

### Добавление публичного ключа на роутер

1. **Через WinBox:**
   - Откройте WinBox → System → Users
   - Выберите пользователя → Нажмите "SSH Keys"
   - Вставьте публичный ключ из `~/.ssh/id_ed25519.pub`

2. **Через Terminal:**
   ```bash
   # Копировать публичный ключ
   cat ~/.ssh/id_ed25519.pub

   # Вставить в терминал RouterOS
   /user ssh-keys import public-key-file=your_key.pub user=admin
   ```

### Запуск аудита с SSH ключом

```bash
python -m src.cli --ssh-user admin --ssh-key-file ~/.ssh/id_ed25519 --router-ip 192.168.1.1
```

---

## ❌ Устранение проблем

### Ошибка: "Server not found in known_hosts"

```
SSHConnectionError: Server '192.168.1.1' not found in known_hosts
```

**Решение:**
1. Выполните команду `ssh-keyscan` из Шага 1
2. Проверьте что ключ добавлен (Шаг 2)
3. Проверьте права доступа к known_hosts

### Ошибка: "Permission denied"

**Windows:** Убедитесь что PowerShell запущен от имени администратора
**Linux/Mac:** Проверьте права доступа:
```bash
chmod 600 ~/.ssh/known_hosts
```

### Предупреждение о смене ключа

Если получили предупреждение:
```
WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!
```

Это может означать:
- Роутер был сброшен (нормально)
- MITM атака (проблема безопасности)

**Исправление (только если доверяете роутеру):**
```bash
# Удалить старый ключ
ssh-keygen -R 192.168.1.1

# Добавить новый ключ
ssh-keyscan -H 192.168.1.1 >> ~/.ssh/known_hosts
```

---

## 📍 Расположение файлов known_hosts

| ОС | Путь |
|----|------|
| **Windows** | `C:\Users\<User>\.ssh\known_hosts` |
| **Linux** | `/home/<user>/.ssh/known_hosts` |
| **Mac** | `/Users/<user>/.ssh/known_hosts` |

---

## 🔒 Лучшие практики

1. ✅ **Всегда проверяйте ключи хостов** перед добавлением в known_hosts
2. ✅ **Используйте SSH ключи** вместо паролей когда возможно
3. ✅ **Регулярно обновляйте** known_hosts при сбросе роутеров
4. ✅ **Используйте сильные пароли** для парольных фраз SSH ключей
5. ✅ **Храните приватные ключи в безопасности** с правильными правами доступа

---

## 📚 Дополнительные ресурсы

- [Paramiko Security Policies](https://docs.paramiko.org/en/latest/api/client.html)
- [SSH Best Practices](https://www.ssh.com/academy/ssh/best-practices)
- [OpenSSH known_hosts Format](https://man.openbsd.org/ssh#SSH_KNOWN_HOSTS_FILE_FORMAT)
