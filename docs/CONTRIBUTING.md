# Руководство по внесению вклада в MikroTik Audit

Спасибо за интерес к проекту MikroTik Audit! Это руководство поможет вам внести свой вклад.

## 📋 Содержание

1. [С чего начать](#с-чего-начать)
2. [Как внести вклад](#как-внести-вклад)
3. [Стандарты кода](#стандарты-кода)
4. [Тестирование](#тестирование)
5. [Pull Request](#pull-request)

## 🚀 С чего начать

1. Fork репозиторий
2. Клонируйте вашу копию:
   ```bash
   git clone https://github.com/cubiculus/Mikrotik_audit.git
   cd Mikrotik_audit
   ```
3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

## 💡 Как внести вклад

### Сообщить об ошибке

1. Проверьте существующие Issues
2. Создайте новый Issue с описанием:
   - Шаги для воспроизведения
   - Ожидаемое поведение
   - Фактическое поведение
   - Версия Python и RouterOS

### Предложить улучшение

1. Создайте Issue с меткой "enhancement"
2. Опишите предлагаемое улучшение
3. Обсудите с maintainers

### Добавить код

1. Создайте branch:
   ```bash
   git checkout -b feature/amazing-feature
   ```
2. Внесите изменения
3. Напишите тесты
4. Закоммитьте изменения

## 📝 Стандарты кода

### Python Style Guide

- Следуйте [PEP 8](https://pep8.org/)
- Используйте type hints
- Документируйте функции и классы

### Пример документации

```python
def execute_command(self, command: str) -> Tuple[int, str, str]:
    """
    Выполнить команду на роутере.

    Args:
        command: Команда для выполнения

    Returns:
        Кортеж (exit_status, stdout, stderr)

    Raises:
        SSHConnectionError: Если соединение не удалось
    """
```

### Именование

- Переменные: `snake_case`
- Классы: `PascalCase`
- Константы: `UPPER_CASE`
- Приватные методы: `_prefix`

## 🧪 Тестирование

### Запуск тестов

```bash
# Все тесты
pytest

# С покрытием
pytest --cov=. --cov-report=html

# Конкретный файл
pytest test_config.py -v
```

### Требования к тестам

- Покрытие >80% для нового кода
- Все тесты должны проходить
- Используйте pytest fixtures

### Пример теста

```python
def test_valid_port_range(self):
    """Test valid SSH port values."""
    config = RouterConfig(ssh_port=22)
    assert config.ssh_port == 22

    config = RouterConfig(ssh_port=65535)
    assert config.ssh_port == 65535
```

## 🔀 Pull Request

### Чеклист перед отправкой

- [ ] Код следует PEP 8
- [ ] Все тесты проходят
- [ ] Покрытие тестами достаточное
- [ ] Документация обновлена
- [ ] CHANGELOG обновлён (если нужно)

### Процесс ревью

1. Создайте Pull Request
2. Опишите изменения
3. Дождитесь ревью
4. Исправьте замечания
5. После approval — merge

### Шаблон PR

```markdown
## Описание
Краткое описание изменений

## Тип изменений
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Тестирование
- [ ] Тесты добавлены/обновлены
- [ ] Все тесты проходят

## Чеклист
- [ ] Код следует стандартам проекта
- [ ] Документация обновлена
```

## 📚 Ресурсы

- [Документация Python](https://docs.python.org/3/)
- [PEP 8](https://pep8.org/)
- [Pytest Documentation](https://docs.pytest.org/)
- [GitHub Flow](https://guides.github.com/introduction/flow/)

## 💬 Контакты

- Issues: [GitHub Issues](https://github.com/cubiculus/Mikrotik_audit/issues)
- Discussions: [GitHub Discussions](https://github.com/cubiculus/Mikrotik_audit/discussions)

Спасибо за ваш вклад! 🎉
