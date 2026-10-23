# Capstone 26 — Sandbox Runner with Denylist and Path Jail

Готовая реализация учебного проекта: контролируемый запуск дочерних процессов с предварительными проверками, path jail, таймаутом, ограничением вывода и структурированным результатом.

> **Важно:** это защитный слой для разработки, а не настоящая песочница ОС. Denylist и path jail не дают изоляции уровня namespaces, seccomp, контейнера, gVisor или microVM. Дочерний процесс наследует полномочия пользователя и после запуска способен делать всё, что разрешает ОС. Для недоверенного кода нужна отдельная OS-изоляция, ограничения ресурсов и сети.

## Что реализовано

- `SandboxResult`: `exit_code`, `stdout`, `stderr`, `truncated`, `timed_out`, `denied`, `reason`, `duration_ms` и исходный `argv`.
- `SandboxConfig`: корень проекта, лимиты, denylist, список интерпретаторов и allowlist переменных окружения.
- Проверка basename исполняемого файла, включая абсолютные пути и `.exe`.
- Блокировка inline-кода интерпретаторов (`-c`, `-e`, `--eval`, `--exec`, `--command`).
- Блокировка shell-метасимволов при `shell=False`.
- Path jail на основе `realpath` + `commonpath`: относительные/абсолютные пути, `cwd`, symlink-escape и значения вида `--output=/path`.
- `shell=True` выключен по умолчанию и требует отдельного явного opt-in.
- Очищенное окружение: дочернему процессу передаются только разрешённые переменные.
- Wall-clock timeout с best-effort завершением всей группы процессов.
- Независимое усечение `stdout`/`stderr` с заметным маркером.
- Безопасная самопроверяющаяся демонстрация: ни одна потенциально разрушительная команда не запускается.
- Полный набор pytest-тестов.

## Структура

```text
.
├── main.py
├── tests/
│   ├── test_demo.py
│   └── test_sandbox.py
├── pyproject.toml
├── requirements-dev.txt
├── REPORT.md
└── LICENSE
```

## Быстрый запуск

Требуется Python 3.9+.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python main.py
python -m pytest -v
```

Демонстрация создаёт временный каталог и использует только безвредные Python-скрипты/фикстуры. Она проверяет разрешённый запуск, структурные отказы, выход за path jail, таймаут и усечение вывода. Финальный JSON содержит `all_expectations_met: true`, если всё прошло ожидаемо.

## Минимальный пример API

```python
import sys
from main import Sandbox, SandboxConfig

sandbox = Sandbox(
    SandboxConfig(
        project_root="/absolute/path/to/project",
        timeout_seconds=5.0,
        max_output_bytes=16_384,
    )
)

# Скрипт должен находиться внутри project_root.
result = sandbox.run([sys.executable, "scripts/check.py"])
if result.denied:
    print("refused:", result.reason)
elif result.timed_out:
    print("timeout")
else:
    print(result.exit_code, result.stdout.decode(errors="replace"))
```

## Модель угроз и ограничения

Этот проект останавливает распространённые ошибочные формы вызова до `Popen`, но не защищает от целенаправленного обхода:

- denylist по определению неполон; безопаснее allowlist разрешённых инструментов;
- path jail — проверка строк/`realpath`, а не файловая изоляция; остаются TOCTOU-риски;
- процесс может обращаться к сети и любым доступным пользователю ресурсам, если ОС не ограничивает это отдельно;
- разрешённый бинарник может сам запускать другие программы или интерпретировать конфигурацию;
- лимит вывода применяется после чтения потока и не заменяет лимиты памяти/CPU;
- `shell=True`, даже при явном включении, предназначен только для доверенного ввода.

Для production запускайте такой слой внутри непривилегированного контейнера или microVM, убирайте capabilities, задавайте read-only mounts, network policy, seccomp, cgroups/ulimits и отдельного пользователя.

## Соответствие уроку

Проект покрывает все пункты Capstone Lesson 26: dataclass-конфигурацию и результат, четыре refusal helper, path jail через `realpath`, таймаут, capture, truncation, env scrub, демонстрацию и тесты. Для корректного завершения потомков используется `subprocess.Popen` + `communicate(timeout=...)`: это практическая реализация заявленного в уроке требования «kill process group», которое невозможно надёжно выполнить через один только `subprocess.run`, поскольку при `TimeoutExpired` тот не возвращает PID дочернего процесса.
