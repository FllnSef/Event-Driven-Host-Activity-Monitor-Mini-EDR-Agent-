# Full EDR Agent (Endpoint Detection, Response & YARA Protection)

Кроссплатформенный (Linux / Windows) высокопроизводительный EDR-агент на **C++17**, комбинирующий сетевую разведку, асинхронный мониторинг файловой системы, сигнатурный сканер **YARA** и модуль **автоматического реагирования (Active Response)** с белыми списками для защиты операционной системы.

Проект представляет собой клиентский модуль системы защиты конечных точек (Endpoint Detection and Response), способный выявлять и нейтрализовать угрозы в реальном времени.

---

## 🚀 Ключевые функции и возможности

### 1. ⚡ Модуль автоматического реагирования (Active Responder)
* **Завершение процессов (Process Termination):** Мгновенная отправка сигнала `SIGKILL` (в Linux) или вызов `TerminateProcess` (в Windows) при выявлении аномалии или вредоносной сигнатуры.
* **Система защиты ОС (Whitelist Protection):** Исключение из подсистемы блокировки критически важных системных процессов (`systemd`, `gnome-shell`, `Xorg`, `gdm3`, `VS Code`, PID <= 1000).
* **Начальный базлайн (Initial Baseline):** Запись первичного состояния запущенных процессов при старте системы без случайного «убивания» рабочих приложений.

### 2. 🔍 Сигнатурный анализ (YARA Engine Integration)
* Встроенная интеграция с библиотекой **`libyara`** для сканирования бинарных файлов запущенных процессов прямо на диске.
* Анализ процессов до момента исполнения опасных команд.

### 3. 🚨 Эвристический анализатор аномалий (Process Chain Anomaly Detector)
* Выявление подозрительного запуска процессов из временных и потенциально опасных папок (`/tmp/`, `/dev/shm/`).
* Детекция аномальных родительских цепочек (например, запуск `bash` или `sh` из под браузеров `firefox-esr` / `chrome` или веб-серверов).

### 4. 🌐 Сетевой монитор с резолвингом доменов (Reverse DNS)
* Преобразование удаленных IP-адресов в читаемые доменные имена (`youtube.com`, `telegram.org`, `github.com`) со встроенным потокобезопасным кэшированием.
* Безсбойное сопоставление сокетов с процессами и родительскими PID (PPID) без состояний гонки (Race-Condition Free).

### 5. 📁 Событийный файловый наблюдатель (0% CPU Idle)
* Использование нативных API прерываний ядра ОС (**`inotify`** в Linux / **`ReadDirectoryChangesW`** в Windows) для отслеживания `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`.

---

## 🛠️ Архитектура системы

```
                              ┌───────────────────────────────┐
                              │     Full EDR Agent Core       │
                              └───────────────┬───────────────┘
                                              │
      ┌─────────────────────────┬─────────────┴─────────────┬─────────────────────────┐
      ▼                         ▼                           ▼                         ▼
┌──────────────┐      ┌───────────────────┐       ┌───────────────────┐     ┌───────────────────┐
│ File Watcher │      │  Process Watcher  │       │  Network Watcher  │     │ Active Responder  │
│  (inotify)   │      │ (Proc Meta / PPID)│       │ (/proc/net/tcp /  │     │ (SIGKILL / Whitelist)
└──────┬───────┘      └─────────┬─────────┘       │   Reverse DNS)    │     └─────────┬─────────┘
       │                        │                 └─────────┬─────────┘               │
       │                        ▼                           │                         │
       │              ┌───────────────────┐                 │                         │
       │              │    YARA Engine    │                 │                         │
       │              │   (libyara-dev)   │                 │                         │
       │              └─────────┬─────────┘                 │                         │
       │                        │                           │                         │
       └────────────────────────┴─────────────┬─────────────┴─────────────────────────┘
                                              ▼
                             ┌─────────────────────────────────┐
                             │      Thread-Safe Logger         │
                             │   Console + activity_log.txt    │
                             └─────────────────────────────────┘
```

---

## 💻 Установка зависимостей и сборка

### 1. Установка системных библиотек (Linux / Kali Linux)

Для работы YARA потребуется пакет разработчика `libyara-dev`:

```bash
sudo apt update
sudo apt install libyara-dev g++ -y
```

### 2. Компиляция через Терминал

Обратите внимание на обязательно передаваемый флаг **`-lyara`** для связывания библиотеки:

```bash
g++ -std=c++17 app.cpp -o app -lyara
```

### 3. Настройка автоматической сборки в VS Code

Если вы собираете проект клавишей в VS Code, добавьте `"-lyara"` в `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "type": "cppbuild",
            "label": "C/C++: g++ сборка активного файла",
            "command": "/usr/bin/g++",
            "args": [
                "-fdiagnostics-color=always",
                "-g",
                "${file}",
                "-std=c++17",
                "-o",
                "${fileDirname}/${fileBasenameNoExtension}",
                "-lyara"
            ],
            "problemMatcher": ["$gcc"],
            "group": { "kind": "build", "isDefault": true }
        }
    ]
}
```

---

## 🚀 Запуск программы

Так как EDR-агенту требуется доступ к `/proc/[pid]/fd` всех процессов и право отправлять `SIGKILL`, запускайте его с правами **root**:

```bash
sudo ./app
```

---

## 🔍 Пример логов работы

```text
=================================================================
  FULL EDR AGENT ACTIVE (Files + Web + Processes + YARA + Protect)
=================================================================

[i] Baseline recorded. Monitoring active for NEW processes only.
[i] Monitoring directory: /home/kali/Desktop/Endpoint-Detection-Mini-EDR

[⚙️ PROC_LAUNCH] PID: 53102 | Parent PID: 1511 | App: [gnome-terminal-]
[🌐 WEB_CONNECT] PID: 53115 [firefox-esr] -> 142.250.185.206:443 (Domain: youtube.com)
[🌐 WEB_CONNECT] PID: 53115 [firefox-esr] -> 149.154.167.99:443 (Domain: telegram.org)

[📁 FILE_CREATED]  /home/kali/Desktop/Endpoint-Detection-Mini-EDR/test.txt
[📁 FILE_MODIFIED] /home/kali/Desktop/Endpoint-Detection-Mini-EDR/test.txt

🚨 !!! [⚡ RESPONSE] KILLING PID: 58210 (malware_test) | Reason: Execution from /tmp/ directory
[🛡️ PROTECT] PID 58210 killed by SIGKILL.
```

---

## 🧪 Сценарии тестирования безопасности

### Тест 1. Запуск из временного каталога (`/tmp/`)
1. Скопируйте любой безопасный бинарный файл в папку `/tmp/`:
   ```bash
   cp /bin/ls /tmp/my_test_app
   ```
2. Попробуйте запустить его:
   ```bash
   /tmp/my_test_app
   ```
3. **Результат:** Агент перехватит запуск, отработает правило `Execution from /tmp/ directory`, выдаст аларм `🚨` и заблокирует процесс.

### Тест 2. Сканирование сети и сайтов
Откройте браузер и загляните на несколько ресурсов (`youtube.com`, `github.com`). В файле `activity_log.txt` вы увидите категории `[🌐 WEB_CONNECT]` с правильными доменными именами.

---

## 📄 Лицензия

Проект распространяется под лицензией **MIT**. Использование разрешено в учебных, исследовательских и оборонных целях.