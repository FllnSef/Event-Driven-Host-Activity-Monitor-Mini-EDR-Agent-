# Event-Driven Host Activity Monitor & Threat Detector (Mini-EDR Agent)

Кроссплатформенный (Linux / Windows) высокопроизводительный агент мониторинга активности хоста и обнаружения угроз на **C++17**. Проект сочетает асинхронный событийный мониторинг файловой системы, аудит сетевых соединений в реальном времени с разрешением доменных имен, отслеживание жизненного цикла процессов и модуль эвристического анализа аномальных цепочек выполнения (Threat Hunting / Process Chain Anomaly Detection).

---

## 🚀 Ключевые возможности

### 1. ⚙️ Мониторинг процессов и цепочек выполнения
* Отслеживание запусков и завершений процессов с захватом **PID**, **Parent PID (PPID)** и имени исполняемого файла.
* Извлечение полных путей к бинарным файлам через системные интерфейсы (`/proc/[pid]/exe` на Linux, `QueryFullProcessImageName` на Windows).

### 2. 🚨 Эвристический детектор аномалий (Process Chain Anomaly Detector)
* **Анализ родительских связей:** Выявление подозрительных цепочек, когда браузер (`firefox-esr`, `chrome`) или офисный пакет (`soffice.bin`, `winword.exe`) порождают системные командные оболочки (`bash`, `sh`, `cmd.exe`, `powershell.exe`).
* **Обнаружение Web Shell / RCE:** Фиксация вызова интерактивных интерпретаторов серверами `nginx`, `apache2`, `httpd`.
* **Запуск из недоверенных директорий:** Мгновенный алерт при запуске исполняемых файлов из временных областей оперативной памяти и каталогов подкачки (`/tmp/`, `/dev/shm/`).

### 3. 🌐 Сетевой монитор с резолвингом доменов (Network & Reverse DNS)
* Сопоставление активных TCP-сокетов (`ESTABLISHED`) с конкретными процессами-владельцами без состояния гонки (Race-Condition Free).
* **Reverse DNS Lookup:** Автоматическое преобразование удаленных IP-адресов в читаемые доменные имена (`youtube.com`, `telegram.org`, `github.com`) с потокобезопасным кэшированием запросов.

### 4. 📁 Событийный мониторинг файлов (0% CPU в режиме простоя)
* Перехват файловых событий в реальном времени через прерывания ядра ОС:
  * **Linux:** Подсистема `inotify`.
  * **Windows:** Win32 API `ReadDirectoryChangesW`.
* Отслеживание создания (`FILE_CREATED`), модификации (`FILE_MODIFIED`) и удаления (`FILE_DELETED`) файлов.

### 5. 📝 Потокобезопасное логирование
* Разделение событий по визуальным категориям (`⚙️ [PROC]`, `🌐 [WEB]`, `📁 [FILE]`, `🚨 [ANOMALY]`).
* Автоматическая запись логов в файл `activity_log.txt` с защитой от циклического самоперехвата.

---

## 🛠️ Архитектура системы

```
                             ┌───────────────────────────────┐
                             │       Host Monitor Core       │
                             └───────────────┬───────────────┘
                                             │
      ┌──────────────────────────────┬───────┴──────────────────────┬──────────────────────────────┐
      ▼                              ▼                              ▼                              ▼
┌───────────────────┐      ┌───────────────────┐          ┌───────────────────┐          ┌───────────────────┐
│  Process Watcher  │      │  Anomaly Detector │          │  Network Watcher  │          │ Event File Watcher│
│  (/proc, WinAPI)  │      │  (Heuristics/RCE) │          │  (/proc/net/tcp,  │          │ (inotify, Win32)  │
└─────────┬─────────┘      └─────────┬─────────┘          │   Reverse DNS)    │          └─────────┬─────────┘
          │                          │                    └─────────┬─────────┘                    │
          └──────────────────────────┼──────────────────────────────┴──────────────────────────────┘
                                     ▼
                    ┌─────────────────────────────────┐
                    │      Thread-Safe Logger         │
                    │   Console + activity_log.txt    │
                    └─────────────────────────────────┘
```

---

## 📦 Сборка и запуск

### Требования
* Компилятор стандарта **C++17** (`GCC 8+`, `Clang 7+` или `MSVC 2019+`).
* Права суперпользователя (`root` / `Administrator`) для доступа к дескрипторам процессов и системным сокетам.

### Linux (Debian / Ubuntu / Kali Linux)
```bash
# Сборка проекта
g++ -std=c++17 main.cpp -o host_monitor

# Запуск с правами суперпользователя
sudo ./host_monitor
```

### Windows (MinGW / Visual Studio)
* **MinGW GCC:**
  ```cmd
  g++ -std=c++17 main.cpp -o host_monitor.exe -liphlpapi -lws2_32 -lpsapi
  host_monitor.exe
  ```
* **MSVC (Visual Studio):**
  1. Создайте проект *C++ Console Application*.
  2. В свойствах проекта установите стандарт языка **C++17**.
  3. Скомпилируйте и запустите от имени Администратора.

---

## 🔍 Примеры вывода в лог

```text
=================================================================
  EDR Agent Active: Process Anomaly Detector & Heuristics ON
=================================================================

[⚙️ PROC_LAUNCH]  PID: 53102 | Parent PID: 1511 (systemd) | App: [gnome-terminal-]
[⚙️ PROC_LAUNCH]  PID: 53108 | Parent PID: 53102 (gnome-terminal-) | App: [bash]
[⚙️ PROC_LAUNCH]  PID: 53115 | Parent PID: 1511 (systemd) | App: [firefox-esr]

[🌐 WEB_CONNECT]  PID: 53115 [firefox-esr] -> 142.250.185.206:443 (Domain: youtube.com)
[🌐 WEB_CONNECT]  PID: 53115 [firefox-esr] -> 149.154.167.99:443 (Domain: telegram.org)

[📁 FILE_CREATED]  /home/user/workspace/test.sh
[📁 FILE_MODIFIED] /home/user/workspace/test.sh

[⚙️ PROC_LAUNCH]  PID: 58210 | Parent PID: 53108 (bash) | App: [malicious_script]
🚨 [ANOMALY_ALERT] Execution from Temporary Directory! App: [malicious_script (PID: 58210)] Path: /tmp/malicious_script

[🌐 WEB_DISCONN]  PID: 53115 [firefox-esr] closed connection to 142.250.185.206:443 (youtube.com)
[⚙️ PROC_EXIT]    PID: 58210 | App: [malicious_script]
```

---

## 🧪 Сценарии тестирования

1. **Проверка сетевого мониторинга:** Откройте браузер и перейдите на `youtube.com` или `github.com`. В логах появится событие `[🌐 WEB_CONNECT]` с разрешенным доменным именем.
2. **Проверка детектора аномалий (/tmp execution):**
   ```bash
   cp /bin/ls /tmp/test_tool
   /tmp/test_tool
   ```
   В логе сработает тревога `🚨 [ANOMALY_ALERT] Execution from Temporary Directory!`.
3. **Проверка файловых событий:** Создайте файл `touch notes.txt` в папке проекта — появится событие `[📁 FILE_CREATED]`.

---

## 📄 Лицензия

Проект распространяется под лицензией **MIT**. Разрешено использование в учебных, исследовательских и оборонных целях.