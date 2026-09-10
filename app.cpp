#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
    #include <psapi.h>
#else
    #include <sys/types.h>
    #include <sys/inotify.h>
    #include <unistd.h>
    #include <limits.h>
    #include <dirent.h>
#endif

namespace fs = std::filesystem;

// Упрощенная функция хэширования для демонстрации
std::string calculate_sha256(const std::string& path) {
    try {
        auto size = fs::file_size(path);
        auto time = fs::last_write_time(path).time_since_epoch().count();
        std::stringstream ss;
        ss << std::hex << size << "-" << time;
        return ss.str();
    } catch (...) {
        return "N/A";
    }
}



class EventFileSystemWatcher {
private:
    std::string watchDir;

#ifdef _WIN32
    void windowsWatchLoop() {
        HANDLE hDir = CreateFileA(
            watchDir.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            NULL
        );

        if (hDir == INVALID_HANDLE_VALUE) {
            std::cerr << "[-] Failed to open directory for event monitoring.\n";
            return;
        }

        char buffer[1024];
        DWORD bytesReturned;

        while (true) {
            BOOL success = ReadDirectoryChangesW(
                hDir,
                buffer,
                sizeof(buffer),
                TRUE, // Рекурсивно
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                NULL,
                NULL
            );

            if (success && bytesReturned > 0) {
                FILE_NOTIFY_INFORMATION* event = (FILE_NOTIFY_INFORMATION*)buffer;
                while (true) {
                    // Конвертация широкой строки имени файла в std::string
                    int wideLen = event->FileNameLength / sizeof(WCHAR);
                    std::wstring wfilename(event->FileName, wideLen);
                    std::string filename(wfilename.begin(), wfilename.end());

                    std::string actionStr;
                    switch (event->Action) {
                        case FILE_ACTION_ADDED:          actionStr = "[*] [FILE CREATED]"; break;
                        case FILE_ACTION_REMOVED:        actionStr = "[-] [FILE DELETED]"; break;
                        case FILE_ACTION_MODIFIED:       actionStr = "[!] [FILE MODIFIED]"; break;
                        case FILE_ACTION_RENAMED_OLD_NAME: actionStr = "[~] [FILE RENAMED (OLD)]"; break;
                        case FILE_ACTION_RENAMED_NEW_NAME: actionStr = "[~] [FILE RENAMED (NEW)]"; break;
                        default: actionStr = "[?] [UNKNOWN]"; break;
                    }

                    std::cout << actionStr << " " << watchDir << "\\" << filename << "\n";

                    if (!event->NextEntryOffset) break;
                    event = (FILE_NOTIFY_INFORMATION*)((LPBYTE)event + event->NextEntryOffset);
                }
            }
        }
        CloseHandle(hDir);
    }
#else
    void linuxWatchLoop() {
        int fd = inotify_init();
        if (fd < 0) {
            std::cerr << "[-] inotify_init failed\n";
            return;
        }

        int wd = inotify_add_watch(fd, watchDir.c_str(), IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_TO);
        if (wd < 0) {
            std::cerr << "[-] inotify_add_watch failed for path: " << watchDir << "\n";
            close(fd);
            return;
        }

        char buffer[4096]
            __attribute__ ((aligned(__alignof__(struct inotify_event))));

        while (true) {
            ssize_t len = read(fd, buffer, sizeof(buffer));
            if (len <= 0) continue;

            char* ptr = buffer;
            while (ptr < buffer + len) {
                struct inotify_event* event = (struct inotify_event*)ptr;
                if (event->len > 0) {
                    if (event->mask & IN_CREATE) {
                        std::cout << "[*] [FILE CREATED] " << watchDir << "/" << event->name << "\n";
                    } else if (event->mask & IN_MODIFY) {
                        std::cout << "[!] [FILE MODIFIED] " << watchDir << "/" << event->name << "\n";
                    } else if (event->mask & IN_DELETE) {
                        std::cout << "[-] [FILE DELETED] " << watchDir << "/" << event->name << "\n";
                    }
                }
                ptr += sizeof(struct inotify_event) + event->len;
            }
        }
        inotify_rm_watch(fd, wd);
        close(fd);
    }
#endif

public:
    explicit EventFileSystemWatcher(std::string path) : watchDir(std::move(path)) {}

    void startAsync() {
        std::thread(&EventFileSystemWatcher::watchLoopRunner, this).detach();
    }

private:
    void watchLoopRunner() {
#ifdef _WIN32
        windowsWatchLoop();
#else
        linuxWatchLoop();
#endif
    }
};



class ProcessWatcher {
private:
    std::unordered_map<unsigned long, std::string> knownPids;

public:
    void scan() {
#ifdef _WIN32
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        std::unordered_map<unsigned long, std::string> currentPids;
        if (Process32First(hSnapshot, &pe32)) {
            do {
                unsigned long pid = pe32.th32ProcessID;
                unsigned long ppid = pe32.th32ParentProcessID;
                std::string name = pe32.szExeFile;
                currentPids[pid] = name;

                if (knownPids.find(pid) == knownPids.end()) {
                    std::cout << "[+] [NEW PROCESS] PID: " << pid 
                              << " | PPID: " << ppid 
                              << " | Name: " << name << "\n";
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        knownPids = std::move(currentPids);
#else
       
#endif
    }
};



int main() {
    std::cout << "====================================================\n";
    std::cout << "  Event-Driven Host Activity Monitor Started        \n";
    std::cout << "  (Using OS Native Events: ReadDirectoryChangesW/inotify)\n";
    std::cout << "====================================================\n\n";

    std::string currentPath = fs::current_path().string();

    // Запуск событийного мониторинга файлов в отдельном асинхронном потоке ОС
    EventFileSystemWatcher fileWatcher(currentPath);
    fileWatcher.startAsync();
    std::cout << "[i] Event file watcher active on: " << currentPath << "\n";

    ProcessWatcher procWatcher;
    
    // Главный цикл (процессы опрашиваются, файлы работают полностью на прерываниях ОС)
    while (true) {
        procWatcher.scan();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}