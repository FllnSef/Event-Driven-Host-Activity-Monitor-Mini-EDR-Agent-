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


class Logger {
private:
    static inline std::mutex logMutex;
    static inline std::ofstream logFile;
public:
    static void init(const std::string& filename = "activity_log.txt") {
        logFile.open(filename, std::ios::app);
    }
    static void log(const std::string& msg) {
        std::lock_guard<std::mutex> lock(logMutex);
        std::cout << msg << std::endl;
        if (logFile.is_open()) logFile << msg << std::endl;
    }
};


std::string resolveDomain(const std::string& ipStr) {
    static std::unordered_map<std::string, std::string> dnsCache;
    static std::mutex cacheMutex;

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        if (dnsCache.find(ipStr) != dnsCache.end()) {
            return dnsCache[ipStr];
        }
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ipStr.c_str(), &sa.sin_addr) <= 0) {
        return ipStr;
    }

    char host[NI_MAXHOST];
    // NI_NAMEREQD вернет ошибку, если у IP нет PTR-записи
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


struct ProcessMeta {
    unsigned long pid;
    unsigned long ppid;
    std::string name;
};

ProcessMeta getProcessMeta(unsigned long pid) {
    if (pid == 0) return {0, 0, "<unknown>"};
    ProcessMeta meta = {pid, 0, "<unknown>"};

#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32; pe32.dwSize = sizeof(pe32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == pid) {
                    meta.ppid = pe32.th32ParentProcessID;
                    meta.name = pe32.szExeFile;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
#else
    std::ifstream statFile("/proc/" + std::to_string(pid) + "/stat");
    if (statFile.is_open()) {
        std::string comm;
        char state;
        statFile >> meta.pid >> comm >> state >> meta.ppid;
        if (comm.size() >= 2) {
            meta.name = comm.substr(1, comm.size() - 2);
        }
    }
#endif
    return meta;
}


class ProcessWatcher {
private:
    std::unordered_map<unsigned long, std::string> knownPids;

public:
    void scan() {
        std::unordered_map<unsigned long, std::string> currentPids;

#ifdef _WIN32
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32; pe32.dwSize = sizeof(pe32);
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    unsigned long pid = pe32.th32ProcessID;
                    unsigned long ppid = pe32.th32ParentProcessID;
                    std::string name = pe32.szExeFile;
                    currentPids[pid] = name;

                    if (knownPids.find(pid) == knownPids.end()) {
                        std::stringstream msg;
                        msg << "[⚙️ PROC_LAUNCH]  PID: " << pid << " | Parent PID: " << ppid << " | App: [" << name << "]";
                        Logger::log(msg.str());
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
#else
        for (const auto& entry : fs::directory_iterator("/proc")) {
            std::string name = entry.path().filename().string();
            if (!std::all_of(name.begin(), name.end(), ::isdigit)) continue;

            unsigned long pid = std::stoul(name);
            ProcessMeta meta = getProcessMeta(pid);
            currentPids[pid] = meta.name;

            if (knownPids.find(pid) == knownPids.end()) {
                std::stringstream msg;
                msg << "[⚙️ PROC_LAUNCH]  PID: " << pid << " | Parent PID: " << meta.ppid << " | App: [" << meta.name << "]";
                Logger::log(msg.str());
            }
        }
#endif

        for (const auto& [pid, name] : knownPids) {
            if (currentPids.find(pid) == currentPids.end()) {
                std::stringstream msg;
                msg << "[⚙️ PROC_EXIT]    PID: " << pid << " | App: [" << name << "]";
                Logger::log(msg.str());
            }
        }

        knownPids = std::move(currentPids);
    }
};


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
                            if (targetInodes.count(inode)) {
                                inodeToPidMap[inode] = pid;
                            }
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

#ifdef _WIN32
        ULONG bufferSize = 0;
        GetExtendedTcpTable(NULL, &bufferSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buffer(bufferSize);
        PMIB_TCPTABLE_OWNER_PID pTable = (PMIB_TCPTABLE_OWNER_PID)buffer.data();
        if (GetExtendedTcpTable(pTable, &bufferSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID row = pTable->table[i];
                if (row.dwRemoteAddr == 0) continue; 
                
                struct in_addr rAddr; rAddr.S_un.S_addr = row.dwRemoteAddr;
                char ipBuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &rAddr, ipBuf, sizeof(ipBuf));

                ProcessMeta meta = getProcessMeta(row.dwOwningPid);
                std::string ipStr(ipBuf);
                std::string domainName = resolveDomain(ipStr);
                current.push_back({row.dwOwningPid, meta.ppid, meta.name, ipStr, ntohs((u_short)row.dwRemotePort), domainName});
            }
        }
#else
        struct RawSocket {
            unsigned long inode;
            std::string ip;
            int port;
        };
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
                msg << "[🌐 WEB_CONNECT]  PID: " << conn.pid << " [" << conn.procName << "] -> "
                    << conn.remoteAddr << ":" << conn.remotePort 
                    << " (Domain: " << conn.domain << ")";
                Logger::log(msg.str());
            }
        }

        for (const auto& [key, conn] : knownConnections) {
            if (currentMap.find(key) == currentMap.end()) {
                std::stringstream msg;
                msg << "[🌐 WEB_DISCONN]  PID: " << conn.pid << " [" << conn.procName << "] closed connection to "
                    << conn.remoteAddr << ":" << conn.remotePort << " (" << conn.domain << ")";
                Logger::log(msg.str());
            }
        }

        knownConnections = std::move(currentMap);
    }
};


class EventFileSystemWatcher {
private:
    std::string watchDir;

#ifdef _WIN32
    void windowsWatchLoop() {
        HANDLE hDir = CreateFileA(watchDir.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hDir == INVALID_HANDLE_VALUE) return;
        char buffer[2048]; DWORD bytesReturned;
        while (true) {
            if (ReadDirectoryChangesW(hDir, buffer, sizeof(buffer), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, &bytesReturned, NULL, NULL)) {
                FILE_NOTIFY_INFORMATION* event = (FILE_NOTIFY_INFORMATION*)buffer;
                while (true) {
                    std::wstring wfilename(event->FileName, event->FileNameLength / sizeof(WCHAR));
                    std::string filename(wfilename.begin(), wfilename.end());
                    if (filename.find("activity_log.txt") == std::string::npos) {
                        std::string actionStr = (event->Action == FILE_ACTION_ADDED) ? "[📁 FILE_CREATED] " :
                                                (event->Action == FILE_ACTION_REMOVED) ? "[📁 FILE_DELETED] " : "[📁 FILE_MODIFIED]";
                        Logger::log(actionStr + " " + watchDir + "\\" + filename);
                    }
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
    }
#endif

public:
    explicit EventFileSystemWatcher(std::string path) : watchDir(std::move(path)) {}
    void startAsync() { std::thread(&EventFileSystemWatcher::watchLoopRunner, this).detach(); }
private:
    void watchLoopRunner() {
#ifdef _WIN32
        windowsWatchLoop();
#else
        linuxWatchLoop();
#endif
    }
};


int main() {
    Logger::init();

    Logger::log("=================================================================");
    Logger::log("  EDR Agent Active: Clean Categories & Domain Resolution Enabled");
    Logger::log("=================================================================\n");

    std::string currentPath = fs::current_path().string();

    EventFileSystemWatcher fileWatcher(currentPath);
    fileWatcher.startAsync();

    ProcessWatcher procWatcher;
    NetworkWatcher netWatcher;

    procWatcher.scan();
    netWatcher.scan();

    Logger::log("[i] Monitoring active...\n");

    while (true) {
        procWatcher.scan();
        netWatcher.scan();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return 0;
}