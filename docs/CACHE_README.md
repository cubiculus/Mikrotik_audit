# Кэширование результатов парсинга

## Обзор

`DataParser` теперь поддерживает кэширование результатов парсинга для улучшения производительности при повторном анализе одних и тех же данных.

## Как это работает

Кэширование реализовано на двух уровнях:

### 1. Память (In-Memory Cache)
- Быстрый доступ к данным
- Автоматически очищается при достижении лимита (1000 записей)
- Идеально для последовательных вызовов

### 2. Диск (Disk Cache)
- Сохраняется в директории `.cache` (по умолчанию)
- Использует pickle для сериализации
- Сохраняется между запусками программы
- Параметр `persist=True` для сохранения на диск

## Использование

### Базовое использование с кэшем по умолчанию

```python
from data_parser import DataParser

# Создаем парсер с кэшем по умолчанию
parser = DataParser()

# Первый вызов - парсинг и кэширование
overview = parser.build_network_overview(results)

# Второй вызов - используется кэш (быстрее!)
overview = parser.build_network_overview(results)
```

### Кастомная директория кэша

```python
from pathlib import Path
from data_parser import DataParser

# Указываем свою директорию для кэша
parser = DataParser(cache_dir=Path("./my_custom_cache"))

overview = parser.build_network_overview(results)
```

## Что кэшируется

Кэшируются следующие данные:

- **System Version**: Версия системы MikroTik
- **System Identity**: Идентификатор роутера
- **Interfaces**: Список интерфейсов и их статистика
- **IP Addresses**: Список IP-адресов
- **DHCP Leases**: Список DHCP-аренд
- **Containers**: Информация о контейнерах
- **DNS**: DNS-конфигурация
- **Routing Rules**: Правила маршрутизации
- **Routes**: Таблица маршрутов
- **Mangle Rules**: Правила mangle firewall
- **NAT Rules**: Правила NAT
- **Filter Rules**: Правила filter firewall

## Ключ кэша

Ключ кэша генерируется с использованием MD5-хеша от содержимого вывода команд:

```python
def _get_cache_key(self, command_output: str) -> str:
    """Generate cache key based on content."""
    return hashlib.md5(command_output.encode()).hexdigest()
```

Это означает, что одинаковые результаты команд будут давать одинаковый ключ кэша.

## Очистка кэша

### Очистка памяти

```python
parser = DataParser()
parser._memory_cache.clear()
```

### Полная очистка (включая диск)

```python
import shutil
from data_parser import DataParser

parser = DataParser()
shutil.rmtree(parser.cache_dir)
```

### Удаление только старых файлов кэша

```python
from pathlib import Path
import time
from datetime import timedelta

parser = DataParser()
cache_age_limit = timedelta(days=7)

for cache_file in parser.cache_dir.glob("*.pkl"):
    file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
    if file_age > cache_age_limit:
        cache_file.unlink()
```

## Логирование

Кэширование использует логирование для отладки:

```python
# Cache hit в памяти
logger.debug(f"Cache hit (memory): {cache_key[:8]}")

# Cache hit на диске
logger.debug(f"Cache hit (disk): {cache_key[:8]}")

# При использовании кэшированных данных
logger.debug("Using cached system version")
```

## Производительность

Преимущества кэширования:

1. **Повторные запуски**: При анализе одних и тех же данных кэш ускоряет работу в 10-100 раз
2. **Разработка**: Быстрый прототипинг без повторного парсинга
3. **Большой объем данных**: Экономия времени при работе с большим количеством интерфейсов/правил

## Пример измерения производительности

```python
import time
from data_parser import DataParser

parser = DataParser()

# Первый запуск (без кэша)
start = time.time()
overview = parser.build_network_overview(results)
first_run = time.time() - start
print(f"First run: {first_run:.3f}s")

# Второй запуск (с кэшем)
start = time.time()
overview = parser.build_network_overview(results)
cached_run = time.time() - start
print(f"Cached run: {cached_run:.3f}s")
print(f"Speedup: {first_run/cached_run:.1f}x")
```

## Безопасность

- Кэш хранит только результаты парсинга, не оригинальные данные
- Использует локальную файловую систему
- Рекомендуется периодически очищать кэш для безопасности

## Обратная совместимость

- Статический метод `DataParser.build_network_overview()` удален
- Теперь требуется создавать экземпляр класса
- Обновите код:

**Было:**
```python
overview = DataParser.build_network_overview(results)
```

**Стало:**
```python
parser = DataParser()
overview = parser.build_network_overview(results)
```

## Интеграция с существующим кодом

Все файлы, использующие `DataParser`, обновлены:

- `report_generator.py`: Создает экземпляр парсера с кэшем
- Кэш используется автоматически для всех отчетов

## Отладка

Для проверки работы кэша:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

parser = DataParser()
overview = parser.build_network_overview(results)
```

Вы увидите логи о попаданиях в кэш: