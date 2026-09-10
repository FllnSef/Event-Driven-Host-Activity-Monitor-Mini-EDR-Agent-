#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <thread>
#include <chrono>
#include <filesystem>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <algorithm>
#include <csignal>

// YARA Library
#include <yara.h>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
    #include <iphlpapi.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/types.h>
    #include <sys/inotify.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <dirent.h>
    #include <arpa/inet.h>
    #include <cstring>
#endif

namespace fs = std::filesystem;

// ============================================================================
// 1. ПОТОКОБЕЗОПАСНЫЙ ЛОГГЕР
// ============================================================================
class Logger {
private:
    static inline std::mutex logMutex;
    static inline std::ofstream logFile;
public:
    static void init(const std::string& filename = "activity_log.txt") {
        logFile.open(filename, std::ios::app);
    }
    static void log(const std::string& msg, bool critical = false) {
        std::lock_guard<std::mutex> lock(logMutex);
        std::string prefix = critical ? "🚨 !!! " : "";
        std::cout << prefix << msg << std::endl;
        if (logFile.is_open()) logFile << prefix << msg << std::endl;
    }
};

// ============================================================================
// 2. ДНС РЕЗОЛВЕР (ОПРЕДЕЛЕНИЕ ДОМЕНОВ С КЭШИРОВАНИЕМ)
// ============================================================================
std::string resolveDomain(const std::string& ipStr) {
    static std::unordered_map<std::string, std::string> dnsCache;
    static std::mutex cacheMutex;

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        if (dnsCache.find(ipStr) != dnsCache.end()) return dnsCache[ipStr];
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ipStr.c_str(), &sa.sin_addr) <= 0) return ipStr;

    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
        std::string domainName(host);
        std::lock_guard<std::mutex> lock(cacheMutex);
        dnsCache[ipStr] = domainName;
        return domainName;
    }

    std::lock_guard<std::mutex> lock(cacheMutex);
    dnsCache[ipStr] = "direct-ip";
    return "direct-ip";
}

// ============================================================================
// 3. МЕТАДАННЫЕ ПРОЦЕССА И АКТИВНЫЙ ОТВЕТЧИК (ACTIVE RESPONDER)
// ============================================================================
struct ProcessMeta {
    unsigned long pid;
    unsigned long ppid;
    std::string name;
    std::string exePath;
};

ProcessMeta getProcessMeta(unsigned long pid) {
    if (pid == 0) return {0, 0, "<unknown>", ""};
    ProcessMeta meta = {pid, 0, "<unknown>", ""};

#ifndef _WIN32
    std::ifstream statFile("/proc/" + std::to_string(pid) + "/stat");
    if (statFile.is_open()) {
        std::string comm; char state;
        statFile >> meta.pid >> comm >> state >> meta.ppid;
        if (comm.size() >= 2) meta.name = comm.substr(1, comm.size() - 2);
    }
    char linkPath[PATH_MAX];
    ssize_t len = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), linkPath, sizeof(linkPath)-1);
    if (len != -1) { linkPath[len] = '\0'; meta.exePath = std::string(linkPath); }
#endif
    return meta;
}

class ActiveResponder {
public:
    static bool isProtectedProcess(unsigned long pid, const std::string& name) {
        if (pid <= 1000 || pid == getpid()) return true;
        std::vector<std::string> protectedApps = {
            "systemd", "gdm3", "gnome-shell", "Xorg", "wayland", 
            "code", "node", "dbus-daemon", "pipewire", "pulseaudio", "bash"
        };
        std::string lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        for (const auto& app : protectedApps) {
            if (lowerName.find(app) != std::string::npos) return true;
        }
        return false;
    }

    static void killProcess(unsigned long pid, const std::string& name, const std::string& reason) {
        if (isProtectedProcess(pid, name)) {
            Logger::log("[⚠️ WHITELIST] Skipped kill for system process: " + name + " (PID: " + std::to_string(pid) + ")", true);
            return;
        }
        Logger::log("[⚡ RESPONSE] KILLING PID: " + std::to_string(pid) + " (" + name + ") | Reason: " + reason, true);
#ifndef _WIN32
        kill(pid, SIGKILL);
#endif
    }
};

// ============================================================================
// 4. YARA СКАНЕР
// ============================================================================
class YaraScanner {
private:
    YR_COMPILER* compiler = nullptr;
    YR_RULES* rules = nullptr;

    static int callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
        if (message == CALLBACK_MSG_RULE_MATCHING) {
            YR_RULE* rule = (YR_RULE*)message_data;
            std::string* matchName = (std::string*)user_data;
            *matchName = rule->identifier;
        }
        return CALLBACK_CONTINUE;
    }

public:
    YaraScanner() {
        yr_initialize();
        yr_compiler_create(&compiler);
        const char* ruleString = 
            "rule Detect_Test_Malware { \
                strings: \
                    $s1 = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\" \
                    $s2 = \"CUSTOM_MALWARE_SIGNATURE_TEST\" \
                condition: any of them }";

        yr_compiler_add_string(compiler, ruleString, NULL);
        yr_compiler_get_rules(compiler, &rules);
    }

    ~YaraScanner() {
        if (rules) yr_rules_destroy(rules);
        if (compiler) yr_compiler_destroy(compiler);
        yr_finalize();
    }

    bool scanFile(const std::string& path, std::string& foundRule) {
        if (!fs::exists(path) || fs::is_directory(path)) return false;
        yr_rules_scan_file(rules, path.c_str(), 0, callback, &foundRule, 0);
        return !foundRule.empty();
    }
};

// ============================================================================
// 5. МОДУЛЬ МОНИТОРИНГА ПРОЦЕССОВ И АНОМАЛИЙ (⚙️ PROCESS WATCHER)
// ============================================================================
class ProcessWatcher {
private:
    std::unordered_map<unsigned long, std::string> knownPids;
    YaraScanner yara;
    bool isFirstRun = true;

public:
    void scan() {
        std::unordered_map<unsigned long, std::string> currentPids;

#ifndef _WIN32
        for (const auto& entry : fs::directory_iterator("/proc")) {
            std::string pidStr = entry.path().filename().string();
            if (!std::all_of(pidStr.begin(), pidStr.end(), ::isdigit)) continue;

            unsigned long pid = std::stoul(pidStr);
            ProcessMeta child = getProcessMeta(pid);
            currentPids[pid] = child.name;

            if (knownPids.find(pid) == knownPids.end()) {
                if (!isFirstRun) {
                    ProcessMeta parent = getProcessMeta(child.ppid);
                    Logger::log("[⚙️ PROC_LAUNCH] PID: " + std::to_string(pid) + " | Parent PID: " + std::to_string(child.ppid) + " | App: [" + child.name + "]");

                    // Проверка запуск из /tmp/
                    if (!child.exePath.empty() && (child.exePath.rfind("/tmp/", 0) == 0 || child.exePath.rfind("/dev/shm/", 0) == 0)) {
                        ActiveResponder::killProcess(pid, child.name, "Execution from /tmp/ directory");
                        continue;
                    }

                    // YARA Сканирование
                    std::string match;
                    if (!child.exePath.empty() && yara.scanFile(child.exePath, match)) {
                        ActiveResponder::killProcess(pid, child.name, "YARA Signature Match: " + match);
                    }
                }
            }
        }
#endif
        for (const auto& [pid, name] : knownPids) {
            if (currentPids.find(pid) == currentPids.end() && !isFirstRun) {
                Logger::log("[⚙️ PROC_EXIT]   PID: " + std::to_string(pid) + " | App: [" + name + "]");
            }
        }

        knownPids = std::move(currentPids);
        if (isFirstRun) isFirstRun = false;
    }
};

// ============================================================================
// 6. МОДУЛЬ МОНИТОРИНГА СЕТИ И ВЕБ-САЙТОВ (🌐 NETWORK WATCHER)
// ============================================================================
struct SocketConnection {
    unsigned long pid;
    unsigned long ppid;
    std::string procName;
    std::string remoteAddr;
    int remotePort;
    std::string domain;
    std::string getKey() const { return std::to_string(pid) + "|" + remoteAddr + ":" + std::to_string(remotePort); }
};

class NetworkWatcher {
private:
    std::unordered_map<std::string, SocketConnection> knownConnections;

#ifndef _WIN32
    std::unordered_map<unsigned long, unsigned long> resolveInodesToPid(const std::set<unsigned long>& targetInodes) {
        std::unordered_map<unsigned long, unsigned long> inodeToPidMap;
        if (targetInodes.empty()) return inodeToPidMap;

        for (const auto& entry : fs::directory_iterator("/proc")) {
            std::string name = entry.path().filename().string();
            if (!std::all_of(name.begin(), name.end(), ::isdigit)) continue;

            unsigned long pid = std::stoul(name);
            std::string fdPath = "/proc/" + name + "/fd";
            try {
                for (const auto& fdEntry : fs::directory_iterator(fdPath)) {
                    char linkPath[PATH_MAX];
                    ssize_t len = readlink(fdEntry.path().c_str(), linkPath, sizeof(linkPath) - 1);
                    if (len != -1) {
                        linkPath[len] = '\0';
                        std::string sLink(linkPath);
                        if (sLink.rfind("socket:[", 0) == 0) {
                            unsigned long inode = std::stoul(sLink.substr(8, sLink.size() - 9));
                            if (targetInodes.count(inode)) inodeToPidMap[inode] = pid;
                        }
                    }
                }
            } catch (...) {}
        }
        return inodeToPidMap;
    }
#endif

public:
    void scan() {
        std::vector<SocketConnection> current;
#ifndef _WIN32
        struct RawSocket { unsigned long inode; std::string ip; int port; };
        std::vector<RawSocket> rawSockets;
        std::set<unsigned long> requiredInodes;

        std::ifstream tcpFile("/proc/net/tcp");
        std::string line; std::getline(tcpFile, line);

        while (std::getline(tcpFile, line)) {
            std::stringstream ss(line);
            std::string sl, local, remote, st; unsigned long inode;
            ss >> sl >> local >> remote >> st >> sl >> sl >> sl >> sl >> sl >> inode;

            unsigned int rIp, rPort;
            sscanf(remote.c_str(), "%X:%X", &rIp, &rPort);
            if (rIp == 0 || st != "01") continue;

            struct in_addr rAddrStruct{rIp};
            rawSockets.push_back({inode, inet_ntoa(rAddrStruct), (int)rPort});
            requiredInodes.insert(inode);
        }

        auto inodeMap = resolveInodesToPid(requiredInodes);

        for (const auto& raw : rawSockets) {
            unsigned long pid = inodeMap.count(raw.inode) ? inodeMap[raw.inode] : 0;
            ProcessMeta meta = getProcessMeta(pid);
            std::string domainName = resolveDomain(raw.ip);
            current.push_back({pid, meta.ppid, meta.name, raw.ip, raw.port, domainName});
        }
#endif

        std::unordered_map<std::string, SocketConnection> currentMap;
        for (auto& conn : current) {
            std::string key = conn.getKey();
            currentMap[key] = conn;

            if (knownConnections.find(key) == knownConnections.end()) {
                std::stringstream msg;
                msg << "[🌐 WEB_CONNECT] PID: " << conn.pid << " [" << conn.procName << "] -> "
                    << conn.remoteAddr << ":" << conn.remotePort << " (Domain: " << conn.domain << ")";
                Logger::log(msg.str());
            }
        }

        for (const auto& [key, conn] : knownConnections) {
            if (currentMap.find(key) == currentMap.end()) {
                std::stringstream msg;
                msg << "[🌐 WEB_DISCONN] PID: " << conn.pid << " [" << conn.procName << "] closed connection to "
                    << conn.remoteAddr << ":" << conn.remotePort << " (" << conn.domain << ")";
                Logger::log(msg.str());
            }
        }

        knownConnections = std::move(currentMap);
    }
};

// ============================================================================
// 7. СОБЫТИЙНЫЙ МОНИТОР ФАЙЛОВ (📁 FILE WATCHER)
// ============================================================================
class EventFileSystemWatcher {
private:
    std::string watchDir;
    void linuxWatchLoop() {
#ifndef _WIN32
        int fd = inotify_init();
        if (fd < 0) return;
        int wd = inotify_add_watch(fd, watchDir.c_str(), IN_CREATE | IN_MODIFY | IN_DELETE);
        char buffer[4096];
        while (true) {
            ssize_t len = read(fd, buffer, sizeof(buffer));
            if (len <= 0) continue;
            char* ptr = buffer;
            while (ptr < buffer + len) {
                struct inotify_event* event = (struct inotify_event*)ptr;
                if (event->len > 0 && std::string(event->name).find("activity_log.txt") == std::string::npos) {
                    if (event->mask & IN_CREATE) Logger::log("[📁 FILE_CREATED]  " + watchDir + "/" + event->name);
                    else if (event->mask & IN_MODIFY) Logger::log("[📁 FILE_MODIFIED] " + watchDir + "/" + event->name);
                    else if (event->mask & IN_DELETE) Logger::log("[📁 FILE_DELETED]  " + watchDir + "/" + event->name);
                }
                ptr += sizeof(struct inotify_event) + event->len;
            }
        }
        close(fd);
#endif
    }

public:
    explicit EventFileSystemWatcher(std::string path) : watchDir(std::move(path)) {}
    void startAsync() { std::thread(&EventFileSystemWatcher::linuxWatchLoop, this).detach(); }
};

// ============================================================================
// ТОЧКА ВХОДА (MAIN)
// ============================================================================
int main() {
    Logger::init();

    Logger::log("=================================================================");
    Logger::log("  FULL EDR AGENT ACTIVE (Files + Web + Processes + YARA + Protect)");
    Logger::log("=================================================================\n");

    std::string currentPath = fs::current_path().string();

    // 1. Асинхронный запуск отслеживания файлов
    EventFileSystemWatcher fileWatcher(currentPath);
    fileWatcher.startAsync();

    ProcessWatcher procWatcher;
    NetworkWatcher netWatcher;

    Logger::log("[i] Monitoring directory: " + currentPath);
    Logger::log("[i] EDR System ready. Try creating files, opening sites, or running apps.\n");

    // 2. Главный цикл системы
    while (true) {
        procWatcher.scan();
        netWatcher.scan();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return 0;
}