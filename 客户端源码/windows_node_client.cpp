#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "ip_lease_client.h"
#include "packet_tunnel_client.h"
#include "tcp_config_client.h"
#include "wintun_manager.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

const DWORD kStartupRetryDelayMs = 2000;
std::atomic<bool> g_stop_requested(false);

std::string Trim(const std::string& value) {
    size_t start = 0;
    while (start < value.size() && isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }

    size_t end = value.size();
    while (end > start && isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(start, end - start);
}

std::string StripQuotes(const std::string& value) {
    if (value.size() >= 2) {
        const char first = value.front();
        const char last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return value.substr(1, value.size() - 2);
        }
    }
    return value;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }
    int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, NULL, 0);
    if (required <= 1) {
        return std::wstring();
    }
    std::wstring out(required - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &out[0], required);
    return out;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }
    int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, NULL, 0, NULL, NULL);
    if (required <= 1) {
        return std::string();
    }
    std::string out(required - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &out[0], required, NULL, NULL);
    return out;
}

std::string NormalizeLogLevel(std::string level) {
    std::transform(level.begin(),
                   level.end(),
                   level.begin(),
                   [](unsigned char ch) { return static_cast<char>(toupper(ch)); });
    if (level == "DEBUG" || level == "INFO" || level == "WARN" || level == "ERROR") {
        return level;
    }
    return "INFO";
}

std::string ReadEnvString(const char* name) {
    DWORD required = GetEnvironmentVariableA(name, NULL, 0);
    if (required == 0) {
        return std::string();
    }
    std::string value(required, '\0');
    DWORD written = GetEnvironmentVariableA(name, &value[0], required);
    if (written == 0 || written >= required) {
        return std::string();
    }
    value.resize(written);
    return value;
}

std::string DetectInitialLogLevel() {
    std::string level = ReadEnvString("DNF_WINDOWS_NODE_LOG_LEVEL");
    if (!level.empty()) {
        return NormalizeLogLevel(level);
    }
    level = ReadEnvString("DNF_PROXY_LOG_LEVEL");
    if (!level.empty()) {
        return NormalizeLogLevel(level);
    }
    return "INFO";
}

class NodeLogger {
public:
    static void Init() {
        CreateDirectoryA("log", NULL);
        SetLevel(DetectInitialLogLevel());

        SYSTEMTIME st = {};
        GetLocalTime(&st);
        char filename[MAX_PATH] = {};
        std::snprintf(filename,
                      sizeof(filename),
                      "log\\windows_node_client_%04u%02u%02u_%02u%02u%02u.txt",
                      st.wYear,
                      st.wMonth,
                      st.wDay,
                      st.wHour,
                      st.wMinute,
                      st.wSecond);

        std::lock_guard<std::mutex> lock(Mutex());
        File().open(filename, std::ios::out | std::ios::app);
        FileEnabled() = File().is_open();
        LogUnlocked("INFO", std::string("[日志] 日志文件=") + filename);
    }

    static void Close() {
        std::lock_guard<std::mutex> lock(Mutex());
        if (File().is_open()) {
            File().flush();
            File().close();
        }
        FileEnabled() = false;
    }

    static void SetLevel(const std::string& level) {
        CurrentLevel() = NormalizeLogLevel(level);
    }

    static bool IsDebugEnabled() {
        return CurrentLevel() == "DEBUG";
    }

    static void Debug(const std::string& msg) { Log("DEBUG", msg); }
    static void Info(const std::string& msg) { Log("INFO", msg); }
    static void Warn(const std::string& msg) { Log("WARN", msg); }
    static void Error(const std::string& msg) { Log("ERROR", msg); }

private:
    static std::ofstream& File() {
        static std::ofstream file;
        return file;
    }

    static bool& FileEnabled() {
        static bool enabled = false;
        return enabled;
    }

    static std::string& CurrentLevel() {
        static std::string level = "INFO";
        return level;
    }

    static std::mutex& Mutex() {
        static std::mutex mutex;
        return mutex;
    }

    static bool ShouldLog(const std::string& level) {
        int level_priority = 1;
        if (level == "DEBUG") level_priority = 0;
        else if (level == "INFO") level_priority = 1;
        else if (level == "WARN") level_priority = 2;
        else if (level == "ERROR") level_priority = 3;

        int current_priority = 1;
        if (CurrentLevel() == "DEBUG") current_priority = 0;
        else if (CurrentLevel() == "INFO") current_priority = 1;
        else if (CurrentLevel() == "WARN") current_priority = 2;
        else if (CurrentLevel() == "ERROR") current_priority = 3;

        return level_priority >= current_priority;
    }

    static const char* DisplayLevel(const std::string& level) {
        if (level == "DEBUG") return "调试";
        if (level == "INFO") return "信息";
        if (level == "WARN") return "警告";
        if (level == "ERROR") return "错误";
        return level.c_str();
    }

    static std::string NowString() {
        SYSTEMTIME st = {};
        GetLocalTime(&st);
        char buffer[64] = {};
        std::snprintf(buffer,
                      sizeof(buffer),
                      "%04u-%02u-%02u %02u:%02u:%02u.%03u",
                      st.wYear,
                      st.wMonth,
                      st.wDay,
                      st.wHour,
                      st.wMinute,
                      st.wSecond,
                      st.wMilliseconds);
        return buffer;
    }

    static void LogUnlocked(const std::string& level, const std::string& msg) {
        std::string line = NowString() + " [" + DisplayLevel(level) + "] " + msg + "\n";
        std::cout << line;
        std::cout.flush();
        if (FileEnabled() && File().is_open()) {
            File() << line;
            if (level == "WARN" || level == "ERROR") {
                File().flush();
            }
        }
    }

    static void Log(const std::string& level, const std::string& msg) {
        if (!ShouldLog(level)) {
            return;
        }
        std::lock_guard<std::mutex> lock(Mutex());
        LogUnlocked(level, msg);
    }
};

void LogDebug(const std::string& msg) { NodeLogger::Debug(msg); }
void LogInfo(const std::string& msg) { NodeLogger::Info(msg); }
void LogWarn(const std::string& msg) { NodeLogger::Warn(msg); }
void LogError(const std::string& msg) { NodeLogger::Error(msg); }

bool SleepStopAware(DWORD total_ms) {
    DWORD elapsed = 0;
    while (!g_stop_requested && elapsed < total_ms) {
        const DWORD slice = std::min<DWORD>(200, total_ms - elapsed);
        Sleep(slice);
        elapsed += slice;
    }
    return g_stop_requested.load();
}

std::string GenerateSessionUuid() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dist(0, 0xFFFFFFFFu);

    unsigned int a = dist(gen);
    unsigned int b = dist(gen);
    unsigned int c = dist(gen);
    unsigned int d = dist(gen);

    std::ostringstream stream;
    stream << std::hex << std::setfill('0')
           << std::setw(8) << a << "-"
           << std::setw(4) << ((b >> 16) & 0xFFFFu) << "-"
           << std::setw(4) << (b & 0xFFFFu) << "-"
           << std::setw(4) << ((c >> 16) & 0xFFFFu) << "-"
           << std::setw(4) << (c & 0xFFFFu)
           << std::setw(8) << d;
    return stream.str();
}

std::string GetHostnameClientId() {
    char name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameA(name, &size) && size > 0) {
        return std::string(name, size);
    }
    return "windows-node";
}

bool IsRunningAsAdmin() {
    BOOL is_admin = FALSE;
    PSID admin_group = NULL;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_authority,
                                 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 &admin_group)) {
        CheckTokenMembership(NULL, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin == TRUE;
}

std::string ExtractRawJsonValue(const std::string& json, const std::string& key) {
    const std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return std::string();
    }

    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return std::string();
    }

    ++pos;
    while (pos < json.size() &&
           (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) {
        ++pos;
    }
    if (pos >= json.size()) {
        return std::string();
    }

    if (json[pos] == '"') {
        size_t end = pos + 1;
        while (true) {
            end = json.find('"', end);
            if (end == std::string::npos) {
                return std::string();
            }
            if (json[end - 1] != '\\') {
                break;
            }
            ++end;
        }
        return json.substr(pos, end - pos + 1);
    }

    size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ']') {
        ++end;
    }
    return json.substr(pos, end - pos);
}

std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string raw = ExtractRawJsonValue(json, key);
    if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"') {
        return std::string();
    }
    return raw.substr(1, raw.size() - 2);
}

int ExtractJsonInt(const std::string& json, const std::string& key, int default_value) {
    std::string raw = ExtractRawJsonValue(json, key);
    if (raw.empty()) {
        return default_value;
    }
    return atoi(raw.c_str());
}

std::vector<std::string> SplitObjectsFromArray(const std::string& json, const std::string& array_key) {
    std::vector<std::string> objects;
    const std::string search = "\"" + array_key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return objects;
    }

    size_t start = json.find('[', pos);
    if (start == std::string::npos) {
        return objects;
    }

    int depth = 0;
    size_t object_start = std::string::npos;
    for (size_t i = start + 1; i < json.size(); ++i) {
        char ch = json[i];
        if (ch == '{') {
            if (depth == 0) {
                object_start = i;
            }
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0 && object_start != std::string::npos) {
                objects.push_back(json.substr(object_start, i - object_start + 1));
                object_start = std::string::npos;
            }
        } else if (ch == ']' && depth == 0) {
            break;
        }
    }
    return objects;
}

std::vector<std::string> GetDefaultConfigPaths() {
    std::vector<std::string> paths;
    paths.push_back(".\\dnf-windows-node-client.conf");
    paths.push_back(".\\dnf-linux-client.conf");
    paths.push_back(".\\client.conf");

    std::string program_data = ReadEnvString("ProgramData");
    if (!program_data.empty()) {
        paths.push_back(program_data + "\\DNFProxy\\windows-node-client.conf");
        paths.push_back(program_data + "\\DNFProxy\\dnf-linux-client.conf");
    }
    return paths;
}

bool FileExists(const std::string& path) {
    DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::string DetectConfigPath(const std::string& requested_path) {
    if (!requested_path.empty()) {
        return FileExists(requested_path) ? requested_path : std::string();
    }

    std::vector<std::string> paths = GetDefaultConfigPaths();
    for (size_t i = 0; i < paths.size(); ++i) {
        if (FileExists(paths[i])) {
            return paths[i];
        }
    }
    return std::string();
}

struct Options {
    std::string api_url;
    int api_port;
    std::string server_key;
    std::string server_virtual_ip;
    std::string client_id;
    std::string preferred_ip;
    std::string if_name;
    std::string session_uuid;
    std::string tunnel_host;
    std::string config_path;
    int tunnel_port;

    Options()
        : api_port(0),
          tunnel_port(0) {}
};

bool LoadConfigFile(const std::string& path, Options* options, std::string* error) {
    if (options == NULL) {
        if (error != NULL) {
            *error = "options is null";
        }
        return false;
    }

    std::ifstream file(path.c_str());
    if (!file.is_open()) {
        if (error != NULL) {
            *error = "open config failed: " + path;
        }
        return false;
    }

    std::string line;
    int line_number = 0;
    while (std::getline(file, line)) {
        ++line_number;

        size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        comment_pos = line.find(';');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }

        line = Trim(line);
        if (line.empty()) {
            continue;
        }

        size_t equal_pos = line.find('=');
        if (equal_pos == std::string::npos) {
            if (error != NULL) {
                *error = "无效的配置行 " + std::to_string(line_number) + ": " + line;
            }
            return false;
        }

        std::string key = Trim(line.substr(0, equal_pos));
        std::string value = StripQuotes(Trim(line.substr(equal_pos + 1)));

        if (key == "api_url") {
            options->api_url = value;
        } else if (key == "api_port") {
            options->api_port = atoi(value.c_str());
        } else if (key == "server_key") {
            options->server_key = value;
        } else if (key == "server_virtual_ip") {
            options->server_virtual_ip = value;
        } else if (key == "client_id") {
            options->client_id = value;
        } else if (key == "preferred_ip") {
            options->preferred_ip = value;
        } else if (key == "if_name") {
            options->if_name = value;
        } else if (key == "session_uuid") {
            options->session_uuid = value;
        } else if (key == "tunnel_host") {
            options->tunnel_host = value;
        } else if (key == "tunnel_port") {
            options->tunnel_port = atoi(value.c_str());
        } else if (key == "config_path") {
            options->config_path = value;
        } else {
            if (error != NULL) {
                *error = "unknown config key at line " + std::to_string(line_number) + ": " + key;
            }
            return false;
        }
    }
    return true;
}

void ApplyDefaultValues(Options* options) {
    if (options == NULL) {
        return;
    }
    if (options->if_name.empty()) {
        options->if_name = "dnfcli0";
    }
    if (options->session_uuid.empty()) {
        options->session_uuid = GenerateSessionUuid();
    }
    if (options->client_id.empty()) {
        options->client_id = GetHostnameClientId();
    }
}

void PrintUsage() {
    std::cout
        << "Usage:\n"
        << "  DNF_Windows_Node_Client_v1.0.exe [--config FILE] [options]\n\n"
        << "Config search order:\n"
        << "  .\\dnf-windows-node-client.conf\n"
        << "  .\\dnf-linux-client.conf\n"
        << "  .\\client.conf\n"
        << "  %ProgramData%\\DNFProxy\\windows-node-client.conf\n"
        << "  %ProgramData%\\DNFProxy\\dnf-linux-client.conf\n\n"
        << "Required when no config file is present:\n"
        << "  --api-url HOST --api-port PORT\n"
        << "  --server-virtual-ip IP  (recommended when multiple nodes exist)\n\n"
        << "Options:\n"
        << "  --config FILE          Load key=value config file\n"
        << "  --server-key KEY       Select node by id/key\n"
        << "  --server-virtual-ip IP Select node by server virtual IP\n"
        << "  --preferred-ip IP      Request a preferred virtual IP\n"
        << "  --client-id ID         Stable client identity, defaults to hostname\n"
        << "  --if-name NAME         Wintun adapter name, default dnfcli0\n"
        << "  --session-uuid UUID    Reuse a fixed session UUID\n"
        << "  --tunnel-host HOST     Override tunnel host from GET_SERVERS\n"
        << "  --tunnel-port PORT     Override tunnel port from GET_SERVERS\n";
}

bool ParseArgs(int argc, char** argv, Options* options) {
    if (options == NULL) {
        return false;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--config" || arg == "-c") && i + 1 < argc) {
            options->config_path = argv[++i];
            break;
        }
    }

    std::string detected_config = DetectConfigPath(options->config_path);
    if (!detected_config.empty()) {
        std::string config_error;
        if (!LoadConfigFile(detected_config, options, &config_error)) {
            LogError("加载配置失败: " + config_error);
            return false;
        }
        options->config_path = detected_config;
    } else if (!options->config_path.empty()) {
        LogError("未找到配置文件: " + options->config_path);
        return false;
    }

    std::map<std::string, std::string*> string_flags;
    string_flags["--api-url"] = &options->api_url;
    string_flags["--server-key"] = &options->server_key;
    string_flags["--server-virtual-ip"] = &options->server_virtual_ip;
    string_flags["--client-id"] = &options->client_id;
    string_flags["--preferred-ip"] = &options->preferred_ip;
    string_flags["--if-name"] = &options->if_name;
    string_flags["--session-uuid"] = &options->session_uuid;
    string_flags["--tunnel-host"] = &options->tunnel_host;
    string_flags["--config"] = &options->config_path;
    string_flags["-c"] = &options->config_path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            return false;
        }

        if (arg == "--api-port" || arg == "--tunnel-port") {
            if (i + 1 >= argc) {
                return false;
            }
            int value = atoi(argv[++i]);
            if (arg == "--api-port") {
                options->api_port = value;
            } else {
                options->tunnel_port = value;
            }
            continue;
        }

        if (arg == "--config" || arg == "-c") {
            if (i + 1 >= argc) {
                return false;
            }
            ++i;
            continue;
        }

        std::map<std::string, std::string*>::iterator it = string_flags.find(arg);
        if (it == string_flags.end() || i + 1 >= argc) {
            return false;
        }
        *(it->second) = argv[++i];
    }

    ApplyDefaultValues(options);
    return !options->api_url.empty() && options->api_port > 0;
}

bool FindServerInfo(const std::vector<ServerInfo>& servers,
                    const std::string& server_selector,
                    ServerInfo* out_server) {
    if (out_server == NULL) {
        return false;
    }

    for (size_t i = 0; i < servers.size(); ++i) {
        if (std::to_string(servers[i].id) == server_selector ||
            WideToUtf8(servers[i].name) == server_selector ||
            servers[i].server_virtual_ip == server_selector) {
            *out_server = servers[i];
            return true;
        }
    }
    return false;
}

TunnelLeaseRuntimeConfig BuildRuntimeConfig(const Options& options,
                                            const ServerInfo& server_info,
                                            const ip_tunnel::LeaseGrant& lease) {
    TunnelLeaseRuntimeConfig runtime;
    runtime.adapter_name = options.if_name;
    runtime.server_virtual_ip = lease.server_virtual_ip;
    runtime.virtual_ip = lease.virtual_ip;
    runtime.subnet_mask = lease.subnet_mask;
    runtime.gateway_ip = lease.gateway_ip;
    runtime.mtu = lease.mtu;
    runtime.routes = lease.routes;
    if (runtime.routes.empty() && !server_info.virtual_subnet.empty()) {
        runtime.routes.push_back(ip_tunnel::RouteEntry(server_info.virtual_subnet));
    }
    return runtime;
}

std::string WStringErrorToUtf8(const std::wstring& value) {
    std::string text = WideToUtf8(value);
    return text.empty() ? "未知错误" : text;
}

bool IsLeaseServerUnavailableError(const std::string& error) {
    return error.find("租约服务器响应超时") != std::string::npos ||
           error.find("租约服务器连接被对端关闭") != std::string::npos ||
           error.find("无法连接到租约服务器") != std::string::npos ||
           error.find("发送租约命令失败") != std::string::npos ||
           error.find("接收租约响应失败") != std::string::npos ||
           error.find("lease server returned empty response") != std::string::npos ||
           error.find("cannot connect to lease server: ") == 0 ||
           error.find("send lease command failed") == 0;
}

void ReleaseLeaseForShutdown(IPLeaseClient* lease_client,
                             const Options& options,
                             const std::string& effective_server_key,
                             const std::string& virtual_ip) {
    if (lease_client == NULL || effective_server_key.empty() || options.session_uuid.empty()) {
        return;
    }

    std::wstring release_error;
    if (!lease_client->ReleaseLease(options.api_url,
                                    options.api_port,
                                    effective_server_key,
                                    options.session_uuid,
                                    &release_error)) {
        const std::string error = WStringErrorToUtf8(release_error);
        if (IsLeaseServerUnavailableError(error)) {
            LogInfo("释放租约时租约服务不可用，已跳过: " + virtual_ip);
        } else {
            LogWarn("释放租约失败: " + error);
        }
        return;
    }
    LogInfo("租约已释放: " + virtual_ip);
}

BOOL WINAPI ConsoleHandler(DWORD ctrl_type) {
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_stop_requested = true;
        return TRUE;
    default:
        return FALSE;
    }
}

}  // namespace

void PacketTunnelDebugLog(const std::string& msg) {
    LogDebug("[数据隧道] " + msg);
}

void PacketTunnelWarnLog(const std::string& msg) {
    LogWarn("[数据隧道] " + msg);
}

void PacketTunnelInfoLog(const std::string& msg) {
    LogInfo("[数据隧道] " + msg);
}

bool PacketTunnelDebugEnabled() {
    return NodeLogger::IsDebugEnabled();
}

std::vector<ServerInfo> parse_server_list(const std::string& json_str) {
    std::vector<ServerInfo> servers;
    std::vector<std::string> objects = SplitObjectsFromArray(json_str, "servers");
    for (size_t i = 0; i < objects.size(); ++i) {
        ServerInfo info = {};
        info.id = ExtractJsonInt(objects[i], "id", 0);
        info.name = Utf8ToWide(ExtractJsonString(objects[i], "name"));
        info.server_virtual_ip = ExtractJsonString(objects[i], "server_virtual_ip");
        info.tunnel_server_ip = ExtractJsonString(objects[i], "tunnel_server_ip");
        info.tunnel_port = ExtractJsonInt(objects[i], "tunnel_port", 0);
        info.download_url = ExtractJsonString(objects[i], "download_url");
        info.virtual_subnet = ExtractJsonString(objects[i], "virtual_subnet");
        info.virtual_gateway = ExtractJsonString(objects[i], "virtual_gateway");
        info.lease_seconds = static_cast<uint32_t>(ExtractJsonInt(objects[i], "lease_seconds", 0));

        if (info.id <= 0 || info.tunnel_server_ip.empty() || info.tunnel_port <= 0) {
            continue;
        }
        servers.push_back(info);
    }

    if (servers.empty()) {
        throw std::runtime_error("no server entries parsed");
    }
    return servers;
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    NodeLogger::Init();

    Options options;
    if (!ParseArgs(argc, argv, &options)) {
        PrintUsage();
        NodeLogger::Close();
        if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
            return 0;
        }
        return 1;
    }

    if (!IsRunningAsAdmin()) {
        LogError("需要管理员权限运行，用于创建 Wintun 适配器和配置路由");
        NodeLogger::Close();
        return 1;
    }

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    LogInfo("Windows 节点客户端启动");
    LogInfo("日志级别=" + DetectInitialLogLevel());
    LogInfo("会话UUID=" + options.session_uuid);
    if (!options.config_path.empty()) {
        LogInfo("配置文件=" + options.config_path);
    }
    LogInfo("客户端ID=" + options.client_id);
    LogInfo("Wintun适配器=" + options.if_name);

    std::string selected_server_key = options.server_key;
    if (selected_server_key.empty() && !options.server_virtual_ip.empty()) {
        selected_server_key = options.server_virtual_ip;
    }

    if (options.preferred_ip.empty() && !options.server_virtual_ip.empty()) {
        options.preferred_ip = options.server_virtual_ip;
    }

    TcpConfigClient config_client;
    IPLeaseClient lease_client;
    unsigned int startup_attempt = 0;

    while (!g_stop_requested) {
        ++startup_attempt;

        std::vector<ServerInfo> servers;
        std::wstring config_error;
        if (!config_client.GetServerList(options.api_url, options.api_port, servers, config_error)) {
            LogWarn("获取服务器列表失败，2秒后重试: " + WStringErrorToUtf8(config_error));
            SleepStopAware(kStartupRetryDelayMs);
            continue;
        }

        ServerInfo server_info = {};
        std::string effective_selector = selected_server_key;
        if (effective_selector.empty()) {
            if (servers.size() == 1) {
                effective_selector = std::to_string(servers[0].id);
                LogInfo("已自动选择节点: " + effective_selector + " (" + WideToUtf8(servers[0].name) + ")");
            } else {
                LogWarn("未指定节点且获取服务器列表返回了 " +
                        std::to_string(servers.size()) +
                        " 个节点，2秒后重试");
                SleepStopAware(kStartupRetryDelayMs);
                continue;
            }
        }

        if (!FindServerInfo(servers, effective_selector, &server_info)) {
            LogWarn("在服务器列表中未找到节点，2秒后重试: " + effective_selector);
            SleepStopAware(kStartupRetryDelayMs);
            continue;
        }

        const std::string effective_server_key = std::to_string(server_info.id);
        const std::string effective_tunnel_host =
            options.tunnel_host.empty() ? server_info.tunnel_server_ip : options.tunnel_host;
        const int effective_tunnel_port =
            options.tunnel_port > 0 ? options.tunnel_port : server_info.tunnel_port;

        ip_tunnel::LeaseRequest lease_request;
        lease_request.server_key = effective_server_key;
        lease_request.session_uuid = options.session_uuid;
        lease_request.client_id = options.client_id;
        lease_request.preferred_ip = options.preferred_ip;

        ip_tunnel::LeaseGrant lease;
        std::wstring lease_error;
        if (!lease_client.RequestLease(options.api_url, options.api_port, lease_request, &lease, &lease_error)) {
            LogWarn("申请租约失败，2秒后重试: " + WStringErrorToUtf8(lease_error));
            SleepStopAware(kStartupRetryDelayMs);
            continue;
        }

        LogInfo("已获取租约: 虚拟IP=" + lease.virtual_ip +
                " 网关=" + lease.gateway_ip +
                " 服务器虚拟IP=" + lease.server_virtual_ip);

        WintunManager wintun_manager;
        TunnelLeaseRuntimeConfig runtime_config = BuildRuntimeConfig(options, server_info, lease);
        std::wstring wintun_error;
        if (!wintun_manager.Setup(runtime_config, &wintun_error)) {
            LogWarn("Wintun 初始化失败，2秒后重试: " + WStringErrorToUtf8(wintun_error));
            ReleaseLeaseForShutdown(&lease_client, options, effective_server_key, lease.virtual_ip);
            SleepStopAware(kStartupRetryDelayMs);
            continue;
        }

        std::wstring network_error;
        if (!wintun_manager.ActivateNetwork(runtime_config, &network_error)) {
            LogWarn("Wintun 网络配置失败，2秒后重试: " + WStringErrorToUtf8(network_error));
            wintun_manager.Cleanup();
            ReleaseLeaseForShutdown(&lease_client, options, effective_server_key, lease.virtual_ip);
            SleepStopAware(kStartupRetryDelayMs);
            continue;
        }

        LogInfo("Wintun 已就绪: 接口=" + options.if_name + " IP=" + lease.virtual_ip);

        std::unique_ptr<PacketTunnelClient> packet_client;
        auto start_packet_client = [&](const ip_tunnel::LeaseGrant& current_lease,
                                       std::wstring* start_error) -> bool {
            packet_client.reset(new PacketTunnelClient(effective_tunnel_host,
                                                       static_cast<uint16_t>(effective_tunnel_port),
                                                       options.session_uuid,
                                                       options.client_id,
                                                       current_lease.server_virtual_ip,
                                                       current_lease.virtual_ip,
                                                       current_lease.mtu,
                                                       &wintun_manager,
                                                       false));
            return packet_client->Start(start_error);
        };

        std::wstring packet_error;
        if (!start_packet_client(lease, &packet_error)) {
            LogWarn("数据隧道启动失败，2秒后重试: " + WStringErrorToUtf8(packet_error));
            if (packet_client) {
                packet_client->Stop();
            }
            wintun_manager.Cleanup();
            ReleaseLeaseForShutdown(&lease_client, options, effective_server_key, lease.virtual_ip);
            SleepStopAware(kStartupRetryDelayMs);
            continue;
        }

        if (startup_attempt > 1) {
            LogInfo("启动恢复成功，第" + std::to_string(startup_attempt) + "次");
        }
        LogInfo("数据隧道已连接: " + effective_tunnel_host + ":" + std::to_string(effective_tunnel_port));

        std::mutex lease_mutex;
        std::atomic<bool> renew_stop(false);
        std::atomic<bool> renew_failed(false);

        auto start_renew_thread = [&]() {
            return std::thread([&]() {
                while (!renew_stop && !g_stop_requested) {
                    uint32_t wait_seconds = 0;
                    {
                        std::lock_guard<std::mutex> lock(lease_mutex);
                        wait_seconds = lease.lease_seconds / 2;
                    }
                    if (wait_seconds < 15) {
                        wait_seconds = 15;
                    }

                    for (uint32_t i = 0; i < wait_seconds && !renew_stop && !g_stop_requested; ++i) {
                        Sleep(1000);
                    }
                    if (renew_stop || g_stop_requested) {
                        break;
                    }

                    ip_tunnel::LeaseGrant renewed;
                    std::wstring renew_error;
                    if (!lease_client.RenewLease(options.api_url,
                                                 options.api_port,
                                                 effective_server_key,
                                                 options.session_uuid,
                                                 &renewed,
                                                 &renew_error)) {
                        renew_failed = true;
                        LogWarn("租约续约失败: " + WStringErrorToUtf8(renew_error));
                        continue;
                    }

                    {
                        std::lock_guard<std::mutex> lock(lease_mutex);
                        lease = renewed;
                    }
                    renew_failed = false;
                    LogInfo("租约续约成功: 虚拟IP=" + renewed.virtual_ip);
                }
            });
        };

        std::thread renew_thread = start_renew_thread();

        while (!g_stop_requested) {
            if (packet_client && packet_client->IsConnected() && !renew_failed) {
                Sleep(200);
                continue;
            }

            if (g_stop_requested) {
                break;
            }

            renew_stop = true;
            if (packet_client) {
                packet_client->Stop();
            }
            if (renew_thread.joinable()) {
                renew_thread.join();
            }

            LogWarn("数据隧道已断开，开始自动恢复");

            std::string previous_virtual_ip;
            {
                std::lock_guard<std::mutex> lock(lease_mutex);
                previous_virtual_ip = lease.virtual_ip;
            }

            ip_tunnel::LeaseGrant recovered_lease;
            std::wstring recover_error;
            if (!lease_client.RenewLease(options.api_url,
                                         options.api_port,
                                         effective_server_key,
                                         options.session_uuid,
                                         &recovered_lease,
                                         &recover_error)) {
                ip_tunnel::LeaseRequest recover_request;
                recover_request.server_key = effective_server_key;
                recover_request.session_uuid = options.session_uuid;
                recover_request.client_id = options.client_id;
                recover_request.preferred_ip = previous_virtual_ip;

                if (!lease_client.RequestLease(options.api_url,
                                               options.api_port,
                                               recover_request,
                                               &recovered_lease,
                                               &recover_error)) {
                    LogWarn("租约恢复失败: " + WStringErrorToUtf8(recover_error));
                    SleepStopAware(kStartupRetryDelayMs);
                    continue;
                }
                LogInfo("已重新申请租约: 虚拟IP=" + recovered_lease.virtual_ip);
            } else {
                LogInfo("已恢复原租约: 虚拟IP=" + recovered_lease.virtual_ip);
            }

            {
                std::lock_guard<std::mutex> lock(lease_mutex);
                lease = recovered_lease;
            }

            runtime_config = BuildRuntimeConfig(options, server_info, recovered_lease);
            std::wstring recover_wintun_error;
            if (!wintun_manager.Setup(runtime_config, &recover_wintun_error)) {
                LogWarn("Wintun 重新初始化失败: " + WStringErrorToUtf8(recover_wintun_error));
                SleepStopAware(kStartupRetryDelayMs);
                continue;
            }

            std::wstring recover_network_error;
            if (!wintun_manager.ActivateNetwork(runtime_config, &recover_network_error)) {
                LogWarn("Wintun 重新配置失败: " + WStringErrorToUtf8(recover_network_error));
                SleepStopAware(kStartupRetryDelayMs);
                continue;
            }

            std::wstring reconnect_error;
            if (!start_packet_client(recovered_lease, &reconnect_error)) {
                LogWarn("数据隧道重连失败: " + WStringErrorToUtf8(reconnect_error));
                SleepStopAware(kStartupRetryDelayMs);
                continue;
            }

            renew_failed = false;
            renew_stop = false;
            renew_thread = start_renew_thread();
            LogInfo("自动重连成功: 虚拟IP=" + recovered_lease.virtual_ip);
        }

        renew_stop = true;
        if (packet_client) {
            packet_client->Stop();
        }
        if (renew_thread.joinable()) {
            renew_thread.join();
        }
        wintun_manager.Cleanup();

        std::string release_virtual_ip;
        {
            std::lock_guard<std::mutex> lock(lease_mutex);
            release_virtual_ip = lease.virtual_ip;
        }
        ReleaseLeaseForShutdown(&lease_client, options, effective_server_key, release_virtual_ip);
    }

    SetConsoleCtrlHandler(ConsoleHandler, FALSE);
    LogInfo("Windows 节点客户端已停止");
    NodeLogger::Close();
    return 0;
}
