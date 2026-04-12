/*
 * DNF游戏代理客户端 - C++ 版本 v12.4.0 (多服务器版)
 * 从自身exe末尾读取配置，支持HTTP API动态获取服务器列表
 *
 * v12.3.14 更新 (2025-11-17):
 * - 🔥 关键修复: TCP握手序列号同步问题，解决频道重选后无法进入游戏
 * - 问题根因: handle_syn()在SYN-ACK后立即设置client_acked_seq，但游戏客户端尚未确认
 * - 修复方案: 在handle_ack()三次握手完成时才正确初始化client_acked_seq
 * - 额外保护: send_window_probe()添加established检查，避免握手未完成时发送探测包
 * - 预期效果: 频道重选后，TCP序列号正确同步，游戏服务器不再发送RST关闭连接
 *
 * v12.3.13 更新 (2025-11-17):
 * - 🔥 关键修复: TCP重传检测，解决频道重选时"无频道"问题
 * - 问题根因: 游戏客户端TCP重传（相同seq号）被转发到服务器，导致协议错误
 * - 修复方案: handle_data()检测seq<server_ack为重传包，忽略数据但发送ACK确认
 * - 预期效果: 重复数据不再转发，服务器协议正常，频道列表正确显示
 *
 * v12.4.0 更新 (2025-11-11):
 * - 🎯 新功能: 服务器切换功能 - 启动时从HTTP API获取服务器列表并显示GUI选择窗口
 * - GUI窗口: Win32原生窗口，仿DNF频道选择风格，支持列表选择和双击连接
 * - 记忆功能: 保存用户上次选择的服务器ID到%APPDATA%\DNFProxy\last_server.ini
 * - API集成: WinHTTP客户端，支持超时控制(5秒连接,10秒接收)
 * - 错误处理: API请求失败直接退出，不回退到单服务器模式
 * - 配置格式: {"config_api_url":"config.server.com","config_api_port":8080,"version_name":"多服务器版v1.0"}
 * - API格式: {"servers":[{"id":1,"name":"龙鸣86","server_virtual_ip":"...","tunnel_server_ip":"...","tunnel_port":33223}]}
 * - 流程优化: 启动流程从5步增加到6步(1.读取API配置 2.获取服务器列表 3.选择服务器 4-6.原有流程)
 *
 * v12.3.12 更新 (2025-11-11):
 * - 🔥 关键修复: TCP握手窗口从1024改为65535，解决游戏客户端窗口被限制问题
 * - 问题根因: advertised_window=1024导致游戏客户端在握手后也使用1024窗口
 * - 测试发现: v12.3.11虽延长运行时间(10分钟→143分钟)，但游戏窗口仍为1024
 * - 根本原因: 代理在SYN-ACK时通告窗口1024，游戏客户端据此设置自己的窗口
 * - 修复方案: advertised_window改为65535，匹配真实游戏客户端握手窗口
 * - 预期效果: 游戏客户端收到65535窗口通告，自行动态调整窗口(200-1000范围)
 * - 技术细节: 握手窗口65535 → 游戏客户端正常窗口行为 → 消除1024固定窗口特征
 *
 * v12.3.11 更新 (2025-11-11):
 * - 🔥 核心修复: TCP窗口动态跟随，解决8-10分钟游戏服务器主动断开问题
 * - 问题根因: data_window固定1024字节，游戏服务器检测到窗口从不变化，判定为代理/外挂特征
 * - 抓包分析: 真实游戏客户端窗口动态变化(200-1000范围)，与代理行为差异过大
 * - 修复方案: data_window改为动态跟随client_window(游戏真实窗口)，消除代理特征
 * - 测试结果: 运行时间从10分钟提升到143分钟，但仍存在1024窗口特征
 * - 技术细节: 窗口变化实时同步，包括窗口缩放(200-1000)和窗口关闭(0)的流控行为
 *
 * v12.3.10 更新 (2025-11-06):
 * - 🔥 关键修复: TCP半关闭机制(SD_SEND)，解决退出副本时队友崩溃问题
 * - 退出时等待send_buffer清空(最多5秒)，确保所有数据发送完成
 * - 停止closing时的窗口探测，避免FIN后序列号混乱
 * - 延长连接清理延迟到2秒，给网络传输留够时间
 * - 预期效果: 退出副本时服务器能完整发送退出响应，队友正常收到通知
 *
 * v12.3.9 更新 (2025-11-06):
 * - 🔥 核心功能: 应用层心跳包保活机制(20秒间隔)，防止NAT/防火墙idle timeout关闭TCP隧道
 * - 增强TCP Keepalive保活机制(30秒探测间隔，5秒重试)，双重保护防止静默断开
 * - recv超时设置为5秒，允许定期发送心跳包保持连接活跃
 * - 客户端和服务端双向心跳(msg_type=0x02)，确保连接双向活跃
 * - 详细诊断隧道断开原因(FIN/RST/超时/中止等)，记录为INFO级别便于排查
 * - 预期效果: 消除3-4分钟idle timeout断线问题，隧道可长期保持稳定
 *
 * v12.3.8 更新 (2025-11-06):
 * - 修复队友看到无响应问题: TCP窗口从1024增大到29200字节
 * - 移除未使用的MAX_SEND_BUFFER旧限制代码
 * - 匹配真实DNF服务器窗口大小，解决多级缓冲区堵塞导致的级联故障
 *
 * v12.3.7 更新 (2025-11-04):
 * - 修复UDP性能瓶颈: hex_dump只在DEBUG级别执行，避免组队卡顿
 * - 优化UDP锁粒度: 减少锁竞争，降低高并发延迟
 * - UDP接收日志改为DEBUG级别，减少磁盘I/O
 * - 增大UDP接收缓冲区到64KB，减少recv()调用
 * - 恢复默认日志级别为INFO，避免性能开销
 *
 * 版本历史详见: VERSION_HISTORY.md
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <shlobj.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <algorithm>

// TCP配置客户端和服务器选择模块
#include "tcp_config_client.h"
#include "ip_lease_client.h"
#include "wintun_manager.h"
#include "packet_tunnel_client.h"
#include "server_selector_gui.h"
#include "config_manager.h"
#include "auto_updater.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
using namespace std;

class LeaseSessionGuard;
class PacketTunnelClient;

static PacketTunnelClient* g_active_packet_tunnel = nullptr;
static LeaseSessionGuard* g_active_lease_session = nullptr;
static atomic<bool> g_shutdown_requested(false);
static atomic<bool> g_shutdown_completed(false);
BOOL WINAPI ClientConsoleCtrlHandler(DWORD ctrl_type);
void RequestGracefulShutdown(const string& reason);

class Logger {
private:
    static ofstream log_file;
    static bool file_enabled;
    static string current_log_level;
    static mutex log_mutex;
    static DWORD last_flush_tick;
    static const DWORD LOG_FLUSH_INTERVAL_MS = 1000;
    static const char* display_level(const string& level) {
        if (level == "DEBUG") return "调试";
        if (level == "INFO") return "信息";
        if (level == "WARN") return "警告";
        if (level == "ERROR") return "错误";
        return level.c_str();
    }

public:
    static void set_log_level(const string& level) {
        current_log_level = level;
    }

    static bool is_debug_enabled() {
        return current_log_level == "DEBUG";
    }

    static void init(const string& filename) {
        lock_guard<mutex> lock(log_mutex);
        log_file.open(filename, ios::out | ios::app);
        if (!log_file.is_open()) {
            return;
        }

        file_enabled = true;
        last_flush_tick = GetTickCount();

        SYSTEMTIME st;
        GetLocalTime(&st);
        char log_line[512];
        sprintf(log_line, "%04d-%02d-%02d %02d:%02d:%02d.%03d [信息] 日志文件已初始化: %s\n",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
               filename.c_str());
        printf("%s", log_line);
        fflush(stdout);

        log_file << log_line;
        log_file.flush();
    }

    static void close() {
        lock_guard<mutex> lock(log_mutex);
        if (!log_file.is_open()) {
            file_enabled = false;
            return;
        }

        log_file.flush();
        log_file.close();
        file_enabled = false;
    }

    static void info(const string& msg) {
        log("INFO", msg);
    }

    static void error(const string& msg) {
        log("ERROR", msg);
    }

    static void warning(const string& msg) {
        log("WARN", msg);
    }

    static void debug(const string& msg) {
        log("DEBUG", msg);
    }

private:
    static void log(const string& level, const string& msg) {
        int level_priority = 0;
        if (level == "DEBUG") level_priority = 0;
        else if (level == "INFO") level_priority = 1;
        else if (level == "WARN") level_priority = 2;
        else if (level == "ERROR") level_priority = 3;

        int current_priority = 0;
        if (current_log_level == "DEBUG") current_priority = 0;
        else if (current_log_level == "INFO") current_priority = 1;
        else if (current_log_level == "WARN") current_priority = 2;
        else if (current_log_level == "ERROR") current_priority = 3;

        if (level_priority < current_priority) return;

        SYSTEMTIME st;
        GetLocalTime(&st);
        char log_line[65536];
        sprintf(log_line, "%04d-%02d-%02d %02d:%02d:%02d.%03d [%s] %s\n",
               st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
               display_level(level), msg.c_str());

        lock_guard<mutex> lock(log_mutex);
        printf("%s", log_line);
        fflush(stdout);

        if (file_enabled && log_file.is_open()) {
            log_file << log_line;

            DWORD now = GetTickCount();
            bool force_flush = (level == "WARN" || level == "ERROR");
            if (force_flush || (now - last_flush_tick >= LOG_FLUSH_INTERVAL_MS)) {
                log_file.flush();
                last_flush_tick = now;
            }
        }
    }
};

ofstream Logger::log_file;
bool Logger::file_enabled = false;
string Logger::current_log_level = "INFO";
mutex Logger::log_mutex;
DWORD Logger::last_flush_tick = 0;

void PacketTunnelDebugLog(const string& msg) {
    Logger::debug("[数据隧道] " + msg);
}

void PacketTunnelWarnLog(const string& msg) {
    Logger::warning("[数据隧道] " + msg);
}

void PacketTunnelInfoLog(const string& msg) {
    Logger::info("[数据隧道] " + msg);
}

bool PacketTunnelDebugEnabled() {
    return Logger::is_debug_enabled();
}

static string normalize_log_level(string level) {
    transform(level.begin(),
              level.end(),
              level.begin(),
              [](unsigned char ch) { return static_cast<char>(toupper(ch)); });
    if (level == "DEBUG" || level == "INFO" || level == "WARN" || level == "ERROR") {
        return level;
    }
    return "INFO";
}

static string determine_initial_log_level() {
    char value[32] = {};
    DWORD length = GetEnvironmentVariableA("DNF_PROXY_LOG_LEVEL",
                                           value,
                                           static_cast<DWORD>(sizeof(value)));
    if (length == 0 || length >= sizeof(value)) {
        return "INFO";
    }
    return normalize_log_level(string(value, length));
}

string g_session_uuid;

bool read_api_config_from_self(string& api_url, int& api_port, string& version_name, string& data_plane_mode) {
    char exe_path[MAX_PATH];
    if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) == 0) {
        return false;
    }

    ifstream file(exe_path, ios::binary | ios::ate);
    if (!file.is_open()) {
        return false;
    }

    streamsize file_size = file.tellg();
    if (file_size < 100) {
        file.close();
        return false;
    }

    const string END_MARKER = "[CONFIG_END]";
    const string START_MARKER = "[CONFIG_START]";
    const int SEARCH_BUFFER_SIZE = 8192;

    int search_size = min((streamsize)SEARCH_BUFFER_SIZE, file_size);
    vector<char> buffer(search_size);
    file.seekg(file_size - search_size, ios::beg);
    file.read(buffer.data(), search_size);
    file.close();

    string tail_content(buffer.data(), search_size);

    size_t end_pos = tail_content.rfind(END_MARKER);
    if (end_pos == string::npos) {
        return false;
    }

    size_t start_pos = tail_content.rfind(START_MARKER, end_pos);
    if (start_pos == string::npos) {
        return false;
    }

    start_pos += START_MARKER.length();
    if (start_pos >= end_pos) {
        return false;
    }

    string json_content = tail_content.substr(start_pos, end_pos - start_pos);

    size_t api_url_pos = json_content.find("\"config_api_url\"");
    if (api_url_pos == string::npos) return false;
    size_t api_url_colon = json_content.find(":", api_url_pos);
    if (api_url_colon == string::npos) return false;
    size_t api_url_quote1 = json_content.find("\"", api_url_colon);
    if (api_url_quote1 == string::npos) return false;
    size_t api_url_quote2 = json_content.find("\"", api_url_quote1 + 1);
    if (api_url_quote2 == string::npos) return false;
    api_url = json_content.substr(api_url_quote1 + 1, api_url_quote2 - api_url_quote1 - 1);

    size_t api_port_pos = json_content.find("\"config_api_port\"");
    if (api_port_pos == string::npos) return false;
    size_t api_port_colon = json_content.find(":", api_port_pos);
    if (api_port_colon == string::npos) return false;
    size_t api_port_comma = json_content.find_first_of(",}", api_port_colon);
    if (api_port_comma == string::npos) return false;

    string port_str = json_content.substr(api_port_colon + 1, api_port_comma - api_port_colon - 1);
    port_str.erase(remove_if(port_str.begin(), port_str.end(), ::isspace), port_str.end());

    try {
        api_port = stoi(port_str);
    } catch (...) {
        return false;
    }

    size_t version_pos = json_content.find("\"version_name\"");
    if (version_pos != string::npos) {
        size_t version_colon = json_content.find(":", version_pos);
        if (version_colon != string::npos) {
            size_t version_quote1 = json_content.find("\"", version_colon);
            if (version_quote1 != string::npos) {
                size_t version_quote2 = json_content.find("\"", version_quote1 + 1);
                if (version_quote2 != string::npos) {
                    version_name = json_content.substr(version_quote1 + 1, version_quote2 - version_quote1 - 1);
                }
            }
        }
    }

    if (version_name.empty()) {
        version_name = "多服务器版";
    }

    data_plane_mode.clear();
    size_t data_plane_pos = json_content.find("\"data_plane_mode\"");
    if (data_plane_pos != string::npos) {
        size_t data_plane_colon = json_content.find(":", data_plane_pos);
        if (data_plane_colon != string::npos) {
            size_t data_plane_quote1 = json_content.find("\"", data_plane_colon);
            if (data_plane_quote1 != string::npos) {
                size_t data_plane_quote2 = json_content.find("\"", data_plane_quote1 + 1);
                if (data_plane_quote2 != string::npos) {
                    data_plane_mode = json_content.substr(data_plane_quote1 + 1,
                                                          data_plane_quote2 - data_plane_quote1 - 1);
                }
            }
        }
    }

    return true;
}

vector<ServerInfo> parse_server_list(const string& json_str) {
    vector<ServerInfo> servers;

    size_t servers_pos = json_str.find("\"servers\"");
    if (servers_pos == string::npos) {
        throw runtime_error("缺少servers字段");
    }

    size_t array_start = json_str.find("[", servers_pos);
    if (array_start == string::npos) {
        throw runtime_error("servers数组格式错误");
    }

    size_t array_end = json_str.find("]", array_start);
    if (array_end == string::npos) {
        throw runtime_error("servers数组未闭合");
    }

    string array_content = json_str.substr(array_start + 1, array_end - array_start - 1);
    size_t pos = 0;
    while (pos < array_content.length()) {
        size_t obj_start = array_content.find("{", pos);
        if (obj_start == string::npos) break;

        size_t obj_end = array_content.find("}", obj_start);
        if (obj_end == string::npos) break;

        string obj_content = array_content.substr(obj_start, obj_end - obj_start + 1);
        ServerInfo info{};

        size_t id_pos = obj_content.find("\"id\"");
        if (id_pos != string::npos) {
            size_t id_colon = obj_content.find(":", id_pos);
            if (id_colon != string::npos) {
                size_t id_end = obj_content.find_first_of(",}", id_colon);
                string id_str = obj_content.substr(id_colon + 1, id_end - id_colon - 1);
                id_str.erase(remove_if(id_str.begin(), id_str.end(), ::isspace), id_str.end());
                info.id = stoi(id_str);
            }
        }

        size_t name_pos = obj_content.find("\"name\"");
        if (name_pos != string::npos) {
            size_t name_colon = obj_content.find(":", name_pos);
            if (name_colon != string::npos) {
                size_t name_quote1 = obj_content.find("\"", name_colon);
                if (name_quote1 != string::npos) {
                    size_t name_quote2 = obj_content.find("\"", name_quote1 + 1);
                    if (name_quote2 != string::npos) {
                        string name_str = obj_content.substr(name_quote1 + 1, name_quote2 - name_quote1 - 1);
                        int len = MultiByteToWideChar(CP_UTF8, 0, name_str.c_str(), -1, NULL, 0);
                        if (len > 0) {
                            vector<wchar_t> wbuf((size_t)len);
                            MultiByteToWideChar(CP_UTF8, 0, name_str.c_str(), -1, wbuf.data(), len);
                            info.name = wbuf.data();
                        }
                    }
                }
            }
        }

        size_t server_ip_pos = obj_content.find("\"server_virtual_ip\"");
        if (server_ip_pos != string::npos) {
            size_t server_ip_colon = obj_content.find(":", server_ip_pos);
            if (server_ip_colon != string::npos) {
                size_t server_ip_quote1 = obj_content.find("\"", server_ip_colon);
                if (server_ip_quote1 != string::npos) {
                    size_t server_ip_quote2 = obj_content.find("\"", server_ip_quote1 + 1);
                    if (server_ip_quote2 != string::npos) {
                        info.server_virtual_ip = obj_content.substr(server_ip_quote1 + 1, server_ip_quote2 - server_ip_quote1 - 1);
                    }
                }
            }
        }

        size_t tunnel_ip_pos = obj_content.find("\"tunnel_server_ip\"");
        if (tunnel_ip_pos != string::npos) {
            size_t tunnel_ip_colon = obj_content.find(":", tunnel_ip_pos);
            if (tunnel_ip_colon != string::npos) {
                size_t tunnel_ip_quote1 = obj_content.find("\"", tunnel_ip_colon);
                if (tunnel_ip_quote1 != string::npos) {
                    size_t tunnel_ip_quote2 = obj_content.find("\"", tunnel_ip_quote1 + 1);
                    if (tunnel_ip_quote2 != string::npos) {
                        info.tunnel_server_ip = obj_content.substr(tunnel_ip_quote1 + 1, tunnel_ip_quote2 - tunnel_ip_quote1 - 1);
                    }
                }
            }
        }

        size_t port_pos = obj_content.find("\"tunnel_port\"");
        if (port_pos != string::npos) {
            size_t port_colon = obj_content.find(":", port_pos);
            if (port_colon != string::npos) {
                size_t port_end = obj_content.find_first_of(",}", port_colon);
                string port_str = obj_content.substr(port_colon + 1, port_end - port_colon - 1);
                port_str.erase(remove_if(port_str.begin(), port_str.end(), ::isspace), port_str.end());
                info.tunnel_port = stoi(port_str);
            }
        }

        size_t download_pos = obj_content.find("\"download_url\"");
        if (download_pos != string::npos) {
            size_t download_colon = obj_content.find(":", download_pos);
            if (download_colon != string::npos) {
                size_t download_quote1 = obj_content.find("\"", download_colon);
                if (download_quote1 != string::npos) {
                    size_t download_quote2 = obj_content.find("\"", download_quote1 + 1);
                    if (download_quote2 != string::npos) {
                        info.download_url = obj_content.substr(download_quote1 + 1, download_quote2 - download_quote1 - 1);
                    }
                }
            }
        }

        servers.push_back(info);
        pos = obj_end + 1;
    }

    return servers;
}

string wstring_to_utf8(const wstring& wstr) {
    if (wstr.empty()) {
        return string();
    }

    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    if (len <= 1) {
        return string();
    }

    string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], len, NULL, NULL);
    return result;
}

wstring utf8_to_wstring(const string& str) {
    if (str.empty()) {
        return wstring();
    }

    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    if (len <= 1) {
        return wstring();
    }

    wstring result(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], len);
    return result;
}

string get_computer_name_string() {
    char computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameA(computer_name, &size) && size > 0) {
        return string(computer_name, size);
    }
    return "unknown-client";
}

wstring get_client_identity_dir() {
    wchar_t appdata_path[MAX_PATH] = {0};
    if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata_path))) {
        return L"";
    }
    return wstring(appdata_path) + L"\\DNFProxy";
}

bool ensure_directory_exists(const wstring& dir_path) {
    if (dir_path.empty()) {
        return false;
    }

    DWORD attr = GetFileAttributesW(dir_path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        return true;
    }

    if (CreateDirectoryW(dir_path.c_str(), NULL)) {
        return true;
    }

    return GetLastError() == ERROR_ALREADY_EXISTS;
}

wstring get_client_identity_file_path() {
    const wstring identity_dir = get_client_identity_dir();
    if (identity_dir.empty()) {
        return L"";
    }
    return identity_dir + L"\\client_identity.ini";
}

uint64_t get_current_time_ms_utc() {
    FILETIME file_time;
    GetSystemTimeAsFileTime(&file_time);

    ULARGE_INTEGER ticks;
    ticks.LowPart = file_time.dwLowDateTime;
    ticks.HighPart = file_time.dwHighDateTime;

    static const uint64_t kUnixEpochOffset100ns = 116444736000000000ULL;
    if (ticks.QuadPart <= kUnixEpochOffset100ns) {
        return 0;
    }
    return (ticks.QuadPart - kUnixEpochOffset100ns) / 10000ULL;
}

string read_machine_guid() {
    HKEY key = NULL;
    LONG open_result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                     L"SOFTWARE\\Microsoft\\Cryptography",
                                     0,
                                     KEY_READ | KEY_WOW64_64KEY,
                                     &key);
    if (open_result != ERROR_SUCCESS) {
        open_result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                    L"SOFTWARE\\Microsoft\\Cryptography",
                                    0,
                                    KEY_READ,
                                    &key);
    }
    if (open_result != ERROR_SUCCESS) {
        return string();
    }

    wchar_t value[256] = {0};
    DWORD type = 0;
    DWORD value_size = sizeof(value);
    LONG query_result = RegQueryValueExW(key,
                                         L"MachineGuid",
                                         NULL,
                                         &type,
                                         reinterpret_cast<LPBYTE>(value),
                                         &value_size);
    RegCloseKey(key);

    if (query_result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || value[0] == L'\0') {
        return string();
    }

    return wstring_to_utf8(value);
}

string bytes_to_hex(const BYTE* data, size_t size) {
    static const char* kHex = "0123456789abcdef";
    string result;
    result.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        result.push_back(kHex[(data[i] >> 4) & 0x0F]);
        result.push_back(kHex[data[i] & 0x0F]);
    }
    return result;
}

string compute_sha256_hex(const string& input) {
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    BYTE digest[32] = {0};
    DWORD digest_size = sizeof(digest);

    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return string();
    }
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(provider, 0);
        return string();
    }
    if (!input.empty() &&
        !CryptHashData(hash,
                       reinterpret_cast<const BYTE*>(input.data()),
                       static_cast<DWORD>(input.size()),
                       0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return string();
    }
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_size, 0)) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return string();
    }

    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    return bytes_to_hex(digest, digest_size);
}

bool load_persisted_client_id(string* client_id, string* created_at_ms = nullptr) {
    const wstring identity_file = get_client_identity_file_path();
    if (identity_file.empty()) {
        return false;
    }

    DWORD attr = GetFileAttributesW(identity_file.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    wchar_t client_id_buf[256] = {0};
    GetPrivateProfileStringW(L"DNFProxy", L"ClientId", L"", client_id_buf, 256, identity_file.c_str());
    if (client_id_buf[0] == L'\0') {
        return false;
    }

    if (client_id != nullptr) {
        *client_id = wstring_to_utf8(client_id_buf);
    }

    if (created_at_ms != nullptr) {
        wchar_t created_at_buf[64] = {0};
        GetPrivateProfileStringW(L"DNFProxy", L"CreatedAtMs", L"", created_at_buf, 64, identity_file.c_str());
        *created_at_ms = wstring_to_utf8(created_at_buf);
    }
    return true;
}

bool persist_client_identity(const string& client_id,
                             uint64_t created_at_ms,
                             const string& source) {
    const wstring identity_dir = get_client_identity_dir();
    const wstring identity_file = get_client_identity_file_path();
    if (identity_dir.empty() || identity_file.empty() || !ensure_directory_exists(identity_dir)) {
        return false;
    }

    wchar_t created_at_buf[64] = {0};
    swprintf(created_at_buf, 64, L"%llu", static_cast<unsigned long long>(created_at_ms));

    return WritePrivateProfileStringW(L"DNFProxy", L"Version", L"1", identity_file.c_str()) == TRUE &&
           WritePrivateProfileStringW(L"DNFProxy", L"ClientId", utf8_to_wstring(client_id).c_str(), identity_file.c_str()) == TRUE &&
           WritePrivateProfileStringW(L"DNFProxy", L"CreatedAtMs", created_at_buf, identity_file.c_str()) == TRUE &&
           WritePrivateProfileStringW(L"DNFProxy", L"Source", utf8_to_wstring(source).c_str(), identity_file.c_str()) == TRUE;
}

string get_local_client_id() {
    string persisted_client_id;
    string persisted_created_at;
    if (load_persisted_client_id(&persisted_client_id, &persisted_created_at) &&
        !persisted_client_id.empty()) {
        Logger::debug("[租约] 客户端ID来源=持久化 创建时间=" +
                      (persisted_created_at.empty() ? string("unknown") : persisted_created_at) +
                      " id=" + persisted_client_id.substr(0, min<size_t>(persisted_client_id.size(), 16)));
        return persisted_client_id;
    }

    const string machine_guid = read_machine_guid();
    const string machine_identity = machine_guid.empty() ? get_computer_name_string() : machine_guid;
    const string source = machine_guid.empty() ? "computer_name_fallback" : "machine_guid";
    const uint64_t created_at_ms = get_current_time_ms_utc();
    const string salt = "dnf-proxy-client-id-v1::20260327";
    string client_id = compute_sha256_hex(machine_identity + "|" +
                                          to_string(created_at_ms) + "|" +
                                          salt);
    if (client_id.empty()) {
        client_id = machine_identity;
    }

    if (!persist_client_identity(client_id, created_at_ms, source)) {
        Logger::warning("[租约] 客户端ID持久化失败，来源=" + source);
    } else {
        Logger::debug("[租约] 已生成客户端ID，来源=" + source +
                      " created_at=" + to_string(created_at_ms) +
                      " id=" + client_id.substr(0, min<size_t>(client_id.size(), 16)));
    }

    return client_id;
}

// 生成简单的UUID (格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
string generate_session_uuid() {
    // 使用时间戳和随机数生成UUID
    SYSTEMTIME st;
    GetLocalTime(&st);

    // 初始化随机数生成器
    srand((unsigned int)time(NULL) ^ GetTickCount());

    char uuid[37];
    sprintf(uuid, "%08x-%04x-%04x-%04x-%08x%04x",
            (unsigned int)(st.wYear * 10000 + st.wMonth * 100 + st.wDay),  // 8位
            (unsigned int)(st.wHour * 100 + st.wMinute),                     // 4位
            (unsigned int)(st.wSecond * 1000 + st.wMilliseconds),           // 4位
            (unsigned int)(rand() % 65536),                                  // 4位
            (unsigned int)GetTickCount(),                                    // 8位
            (unsigned int)(rand() % 65536));                                 // 4位

    return string(uuid);
}

class LeaseSessionGuard {
public:
    LeaseSessionGuard()
        : api_port_(0), active_(false), renew_failed_(false) {}

    ~LeaseSessionGuard() {
        Release();
    }

    bool Acquire(const string& api_url,
                 int api_port,
                 const string& server_key,
                 const string& session_uuid,
                 const string& client_id,
                 wstring& error_msg) {
        lock_guard<mutex> op_lock(op_lock_);
        IPLeaseClient client;
        ip_tunnel::LeaseRequest request;
        request.server_key = server_key;
        request.session_uuid = session_uuid;
        request.client_id = client_id;

        ip_tunnel::LeaseGrant lease;
        if (!client.RequestLease(api_url, api_port, request, &lease, &error_msg)) {
            return false;
        }

        {
            lock_guard<mutex> lock(lock_);
            api_url_ = api_url;
            api_port_ = api_port;
            server_key_ = server_key;
            session_uuid_ = session_uuid;
            client_id_ = client_id;
            lease_ = lease;
        }

        active_ = true;
        renew_failed_ = false;
        renew_thread_ = thread(&LeaseSessionGuard::RenewLoop, this);

        const string route_summary = lease.routes.empty() ? "(无)" : lease.routes[0].cidr;
        Logger::debug("[租约跟踪] 节点键=" + server_key +
                      " 虚拟IP=" + lease.virtual_ip +
                      " 网关=" + lease.gateway_ip +
                      " 服务器虚拟IP=" + lease.server_virtual_ip +
                      " 路由=" + route_summary);

        Logger::info("[租约] 虚拟IP租约申请成功");
        Logger::debug("[租约] 已申请虚拟IP: " + lease.virtual_ip +
                      " 网关=" + lease.gateway_ip +
                      " 租期=" + to_string(lease.lease_seconds) + "秒");
        return true;
    }

    void Release() {
        bool was_active = active_.exchange(false);

        if (renew_thread_.joinable()) {
            renew_thread_.join();
        }

        if (!was_active) {
            return;
        }

        string api_url;
        int api_port = 0;
        string server_key;
        string session_uuid;
        string virtual_ip;

        {
            lock_guard<mutex> lock(lock_);
            api_url = api_url_;
            api_port = api_port_;
            server_key = server_key_;
            session_uuid = session_uuid_;
            virtual_ip = lease_.virtual_ip;
        }

        lock_guard<mutex> op_lock(op_lock_);
        IPLeaseClient client;
        wstring error_msg;
        if (client.ReleaseLease(api_url, api_port, server_key, session_uuid, &error_msg)) {
            Logger::info("[租约] 已释放虚拟IP租约: " + virtual_ip);
        } else if (IsServerUnavailableError(error_msg)) {
            Logger::info("[租约] 租约服务器当前不可用，跳过释放: " + virtual_ip);
        } else {
            Logger::warning("[租约] 释放失败: " + wstring_to_utf8(error_msg));
        }
    }

    ip_tunnel::LeaseGrant GetLease() const {
        lock_guard<mutex> lock(lock_);
        return lease_;
    }

    bool RecoverLease(ip_tunnel::LeaseGrant* recovered_lease, wstring& error_msg) {
        string api_url;
        int api_port = 0;
        string server_key;
        string session_uuid;
        string client_id;
        string preferred_ip;

        {
            lock_guard<mutex> lock(lock_);
            api_url = api_url_;
            api_port = api_port_;
            server_key = server_key_;
            session_uuid = session_uuid_;
            client_id = client_id_;
            preferred_ip = lease_.virtual_ip;
        }

        lock_guard<mutex> op_lock(op_lock_);

        IPLeaseClient client;
        ip_tunnel::LeaseGrant lease;
        if (!client.RenewLease(api_url, api_port, server_key, session_uuid, &lease, &error_msg)) {
            ip_tunnel::LeaseRequest request;
            request.server_key = server_key;
            request.session_uuid = session_uuid;
            request.client_id = client_id;
            request.preferred_ip = preferred_ip;

            if (!client.RequestLease(api_url, api_port, request, &lease, &error_msg)) {
                return false;
            }
            Logger::info("[租约] 已重新申请虚拟IP: " + lease.virtual_ip);
        } else {
            Logger::info("[租约] 已恢复续租: " + lease.virtual_ip);
        }

        {
            lock_guard<mutex> lock(lock_);
            lease_ = lease;
        }
        renew_failed_ = false;

        if (recovered_lease != nullptr) {
            *recovered_lease = lease;
        }
        return true;
    }

private:
    static bool IsServerUnavailableError(const wstring& error_msg) {
        return error_msg.find(L"租约服务器返回空数据") != wstring::npos ||
               error_msg.find(L"无法连接到租约服务器") != wstring::npos ||
               error_msg.find(L"接收租约响应失败") != wstring::npos ||
               error_msg.find(L"发送租约命令失败") != wstring::npos;
    }

    static bool IsLeaseNotFoundError(const wstring& error_msg) {
        return error_msg.find(L"lease not found") != wstring::npos ||
               error_msg.find(L"Lease not found") != wstring::npos ||
               error_msg.find(L"LEASE NOT FOUND") != wstring::npos;
    }

    void RenewLoop() {
        DWORD wait_ms = 30000;

        while (active_) {
            {
                lock_guard<mutex> lock(lock_);
                wait_ms = renew_failed_ ? 5000 : std::max<DWORD>(10000, lease_.lease_seconds * 500);
            }

            DWORD remaining = wait_ms;
            while (active_ && remaining > 0) {
                DWORD slice = std::min<DWORD>(remaining, 1000);
                Sleep(slice);
                remaining -= slice;
            }

            if (!active_) {
                break;
            }

            string api_url;
            int api_port = 0;
            string server_key;
            string session_uuid;
            string client_id;
            string preferred_ip;

            {
                lock_guard<mutex> lock(lock_);
                api_url = api_url_;
                api_port = api_port_;
                server_key = server_key_;
                session_uuid = session_uuid_;
                client_id = client_id_;
                preferred_ip = lease_.virtual_ip;
            }

            lock_guard<mutex> op_lock(op_lock_);
            IPLeaseClient client;
            ip_tunnel::LeaseGrant renewed;
            wstring error_msg;
            if (client.RenewLease(api_url, api_port, server_key, session_uuid, &renewed, &error_msg)) {
                {
                    lock_guard<mutex> lock(lock_);
                    lease_ = renewed;
                }
                renew_failed_ = false;
                Logger::debug("[租约] 续租成功: " + renewed.virtual_ip +
                              " 租期=" + to_string(renewed.lease_seconds) + "秒");
            } else {
                if (IsLeaseNotFoundError(error_msg)) {
                    ip_tunnel::LeaseRequest request;
                    request.server_key = server_key;
                    request.session_uuid = session_uuid;
                    request.client_id = client_id;
                    request.preferred_ip = preferred_ip;

                    ip_tunnel::LeaseGrant reacquired;
                    wstring reacquire_error;
                    if (client.RequestLease(api_url, api_port, request, &reacquired, &reacquire_error)) {
                        {
                            lock_guard<mutex> lock(lock_);
                            lease_ = reacquired;
                        }
                        renew_failed_ = false;
                        Logger::info("[租约] 续租记录丢失，已重新申请虚拟IP: " + reacquired.virtual_ip +
                                     " 租期=" + to_string(reacquired.lease_seconds) + "秒");
                    } else {
                        renew_failed_ = true;
                        Logger::warning("[租约] 续租记录丢失，重新申请失败: " +
                                        wstring_to_utf8(reacquire_error));
                    }
                } else {
                    renew_failed_ = true;
                    Logger::warning("[租约] 续租失败: " + wstring_to_utf8(error_msg));
                }
            }
        }
    }

    mutable mutex lock_;
    mutable mutex op_lock_;
    string api_url_;
    int api_port_;
    string server_key_;
    string session_uuid_;
    string client_id_;
    ip_tunnel::LeaseGrant lease_;
    atomic<bool> active_;
    atomic<bool> renew_failed_;
    thread renew_thread_;
};

void RequestGracefulShutdown(const string& reason) {
    bool expected = false;
    if (!g_shutdown_requested.compare_exchange_strong(expected, true)) {
        return;
    }

    Logger::info("[退出] " + reason);

    if (g_active_packet_tunnel != nullptr) {
        g_active_packet_tunnel->Stop();
    }
    if (g_active_lease_session != nullptr) {
        g_active_lease_session->Release();
    }

    g_shutdown_completed = true;
}

BOOL WINAPI ClientConsoleCtrlHandler(DWORD ctrl_type) {
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        RequestGracefulShutdown("收到控制台退出信号，正在停止客户端");
        return TRUE;
    default:
        return FALSE;
    }
}

// ==================== 主函数 ====================
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    g_shutdown_requested = false;
    g_shutdown_completed = false;

    // 检查是否以worker模式启动（作为子进程）
    bool worker_mode = false;
    int worker_server_id = 0;
    string worker_game_ip;
    string worker_tunnel_ip;
    int worker_tunnel_port = 0;
    string worker_stop_event_name;

    if (argc >= 6 && strcmp(argv[1], "--worker") == 0) {
        worker_mode = true;
        worker_server_id = atoi(argv[2]);
        worker_game_ip = argv[3];
        worker_tunnel_ip = argv[4];
        worker_tunnel_port = atoi(argv[5]);

        for (int i = 6; i < argc; ++i) {
            if (strcmp(argv[i], "--stop-event") == 0 && i + 1 < argc) {
                worker_stop_event_name = argv[i + 1];
                ++i;
            }
        }
    }

    // 隐藏控制台窗口
    HWND console_window = GetConsoleWindow();
    if (console_window != NULL) {
        ShowWindow(console_window, SW_HIDE);
    }

    // 创建log目录（如果不存在）
    CreateDirectoryA("log", NULL);

    // 生成带时间戳的日志文件名
    SYSTEMTIME st;
    GetLocalTime(&st);
    char log_filename[256];
    sprintf(log_filename, "log\\client_log_%04d%02d%02d_%02d%02d%02d.txt",
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // 初始化日志系统
    Logger::init(log_filename);
    const string initial_log_level = determine_initial_log_level();
    Logger::set_log_level(initial_log_level);
    Logger::info("[日志] 默认日志级别: " + initial_log_level);

    // 生成会话UUID
    g_session_uuid = generate_session_uuid();
    Logger::info("[会话] 生成会话UUID: " + g_session_uuid);

    if (worker_mode && !worker_stop_event_name.empty()) {
        HANDLE stop_event = OpenEventA(SYNCHRONIZE, FALSE, worker_stop_event_name.c_str());
        if (stop_event != NULL) {
            Logger::info("[退出] 已连接停止事件: " + worker_stop_event_name);
            std::thread([stop_event]() {
                WaitForSingleObject(stop_event, INFINITE);
                CloseHandle(stop_event);
                RequestGracefulShutdown("收到GUI停止信号，准备优雅退出");
            }).detach();
        } else {
            Logger::warning("[退出] 无法打开停止事件: " + worker_stop_event_name +
                            " (错误=" + to_string(GetLastError()) + ")");
        }
    }

    // 检查管理员权限
    BOOL is_admin = FALSE;
    PSID admin_group = NULL;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(NULL, admin_group, &is_admin);
        FreeSid(admin_group);
    }

    if (!is_admin) {
        cout << "错误: 需要管理员权限" << endl;
        cout << "请右键点击程序，选择\"以管理员身份运行\"" << endl;
        Logger::close();
        MessageBoxW(NULL, L"需要管理员权限\n\n请右键点击程序，选择\"以管理员身份运行\"", L"错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    cout << "============================================================" << endl;
    cout << "DNF游戏代理客户端 v12.4.0 (多服务器版)" << endl;
    cout << "编译时间: " << __DATE__ << " " << __TIME__ << endl;
    cout << "============================================================" << endl;
    cout << endl;

    // ========== 步骤1: 读取API配置并获取服务器列表 ==========
    cout << "[步骤1/6] 读取API配置..." << endl;
    string CONFIG_API_URL;
    int CONFIG_API_PORT;
    string VERSION_NAME;
    string CONFIG_DATA_PLANE_MODE;

    if (!read_api_config_from_self(CONFIG_API_URL, CONFIG_API_PORT, VERSION_NAME, CONFIG_DATA_PLANE_MODE)) {
        cout << "错误: 无法读取API配置" << endl;
        cout << endl;
        cout << "此程序需要配置才能运行。" << endl;
        cout << "请使用配置注入工具生成带配置的客户端程序。" << endl;
        cout << endl;
        Logger::close();
        MessageBoxW(NULL, L"无法读取API配置\n\n此程序需要配置才能运行。\n请使用配置注入工具生成带配置的客户端程序。", L"配置错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    cout << "✓ API配置读取成功" << endl;
    if (Logger::is_debug_enabled()) {
        cout << "  API地址: " << CONFIG_API_URL << ":" << CONFIG_API_PORT << endl;
    }
    cout << endl;

    // ========== 步骤2: 从TCP服务器获取服务器列表 ==========
    cout << "[步骤2/6] 获取服务器列表..." << endl;

    TcpConfigClient tcp_client;
    vector<ServerInfo> servers;
    wstring error_msg;

    if (!tcp_client.GetServerList(CONFIG_API_URL, CONFIG_API_PORT, servers, error_msg)) {
        // 转换wstring到string用于cout输出
        int len = WideCharToMultiByte(CP_UTF8, 0, error_msg.c_str(), -1, NULL, 0, NULL, NULL);
        char* error_str = new char[len];
        WideCharToMultiByte(CP_UTF8, 0, error_msg.c_str(), -1, error_str, len, NULL, NULL);

        cout << "错误: 获取服务器列表失败" << endl;
        cout << "  原因: " << error_str << endl;
        cout << endl;

        // 显示错误消息框
        wstring msg = L"获取服务器列表失败\n\n原因: " + error_msg;
        MessageBoxW(NULL, msg.c_str(), L"网络错误", MB_OK | MB_ICONERROR);

        delete[] error_str;
        Logger::close();
        return 1;
    }

    cout << "✓ 获取到 " << servers.size() << " 个服务器" << endl;
    cout << endl;

    // ========== 步骤2.5: 检查软件更新 ==========
    cout << "[更新检查] 检查软件更新..." << endl;
    Logger::info("[更新检查] 开始检查软件更新");

    AutoUpdater updater;
    UpdateInfo update_info;
    wstring update_error;

    // 计算当前程序的MD5
    string current_md5;
    if (!updater.CalculateSelfMD5(current_md5)) {
        Logger::warning("[更新检查] 无法计算当前程序MD5");
        cout << "  ⚠ 无法计算当前程序MD5，跳过更新检查" << endl;
    } else {
        Logger::info("[更新检查] 当前程序MD5: " + current_md5);
        cout << "  当前MD5: " << current_md5.substr(0, 8) << "..." << endl;

        // 从服务器获取最新版本MD5
        if (updater.GetLatestMD5(CONFIG_API_URL, CONFIG_API_PORT, update_info, update_error)) {
            Logger::info("[更新检查] 服务器MD5: " + update_info.latest_md5);
            cout << "  服务器MD5: " << update_info.latest_md5.substr(0, 8) << "..." << endl;

            // 检查是否需要更新（MD5对比）
            if (updater.NeedsUpdate(current_md5, update_info.latest_md5)) {
                Logger::info("[更新检查] MD5不匹配，发现新版本");
                cout << "  ✓ 发现新版本！" << endl;

                // 保存当前MD5到update_info
                update_info.current_md5 = current_md5;

                // 提示用户并执行更新（如果用户确认，此函数不会返回）
                updater.PromptAndUpdate(update_info);

                // 如果用户取消更新，继续执行
                Logger::info("[更新检查] 用户取消更新，继续运行当前版本");
                cout << "  用户取消更新，继续使用当前版本" << endl;
            } else {
                Logger::info("[更新检查] MD5匹配，当前已是最新版本");
                cout << "  ✓ 当前已是最新版本" << endl;
            }
        } else {
            // 转换错误消息
            int len = WideCharToMultiByte(CP_UTF8, 0, update_error.c_str(), -1, NULL, 0, NULL, NULL);
            char* err_str = new char[len];
            WideCharToMultiByte(CP_UTF8, 0, update_error.c_str(), -1, err_str, len, NULL, NULL);

            Logger::warning("[更新检查] 检查更新失败: " + string(err_str));
            cout << "  ⚠ 无法检查更新: " << err_str << endl;
            cout << "  继续使用当前版本..." << endl;

            delete[] err_str;
        }
    }
    cout << endl;

    // ========== 步骤3: 选择服务器 ==========
    string TUNNEL_SERVER_IP;
    int TUNNEL_PORT;
    int SELECTED_SERVER_ID = 0;

    if (worker_mode) {
        // Worker模式：使用命令行参数
        if (Logger::is_debug_enabled()) {
            cout << "[Worker模式] 使用命令行参数..." << endl;
            cout << "  服务器ID: " << worker_server_id << endl;
            cout << "  服务端虚拟IP: " << worker_game_ip << endl;
            cout << "  隧道服务器: " << worker_tunnel_ip << ":" << worker_tunnel_port << endl;
        }
        cout << endl;

        TUNNEL_SERVER_IP = worker_tunnel_ip;
        TUNNEL_PORT = worker_tunnel_port;
        SELECTED_SERVER_ID = worker_server_id;
    } else {
        // GUI模式：显示服务器选择窗口，GUI将永远运行直到用户关闭
        cout << "[步骤3/6] 启动GUI..." << endl;

        // 读取上次选择的服务器
        ConfigManager config_mgr;
        int last_server_id = config_mgr.LoadLastServer();

        // 显示GUI窗口（这个调用将永远不会返回，除非初始化失败）
        ServerSelectorGUI selector;
        ServerInfo selected_server;

        if (!selector.ShowDialog(servers, last_server_id, selected_server)) {
            cout << "GUI初始化失败" << endl;
            Logger::close();
            MessageBoxW(NULL, L"GUI初始化失败", L"错误", MB_OK | MB_ICONERROR);
            return 1;
        }

        // 这里永远不会到达，因为GUI会一直运行
        // 用户关闭GUI时会调用ExitProcess()直接终止程序
        return 0;
    }

    // ========== Worker模式继续执行 ==========
    // 注意：以下代码只在Worker模式下执行

    LeaseSessionGuard lease_session;
    wstring lease_error_msg;
    string lease_server_key = to_string(SELECTED_SERVER_ID);
    string lease_client_id = get_local_client_id();

    cout << "[租约] 申请虚拟IP租约..." << endl;
    if (!lease_session.Acquire(CONFIG_API_URL, CONFIG_API_PORT,
                               lease_server_key, g_session_uuid, lease_client_id,
                               lease_error_msg)) {
        string lease_error = wstring_to_utf8(lease_error_msg);
        if (lease_error.empty()) {
            lease_error = "未知错误";
        }

        cout << "错误: 虚拟IP租约申请失败" << endl;
        cout << "  原因: " << lease_error << endl;
        Logger::error("[租约] 申请失败: " + lease_error);
        Logger::close();
        MessageBoxW(NULL, (L"虚拟IP租约申请失败\n\n原因: " + lease_error_msg).c_str(), L"网络错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    ip_tunnel::LeaseGrant granted_lease = lease_session.GetLease();
    cout << "✓ 租约申请成功" << endl;
    if (Logger::is_debug_enabled()) {
        cout << "  虚拟IP: " << granted_lease.virtual_ip << endl;
        cout << "  网关: " << granted_lease.gateway_ip << endl;
        cout << "  服务端虚拟IP: " << granted_lease.server_virtual_ip << endl;
        if (!granted_lease.routes.empty()) {
            cout << "  路由: " << granted_lease.routes[0].cidr << endl;
        }
    }
    cout << endl;

    auto BuildLeaseRuntimeConfig = [](const ip_tunnel::LeaseGrant& lease) {
        TunnelLeaseRuntimeConfig runtime;
        runtime.server_virtual_ip = lease.server_virtual_ip;
        runtime.virtual_ip = lease.virtual_ip;
        runtime.subnet_mask = lease.subnet_mask;
        runtime.gateway_ip = lease.gateway_ip;
        runtime.mtu = lease.mtu;
        runtime.routes = lease.routes;
        return runtime;
    };

    TunnelLeaseRuntimeConfig lease_runtime = BuildLeaseRuntimeConfig(granted_lease);

    if (g_shutdown_requested) {
        Logger::info("[退出] 启动阶段收到退出请求，取消继续启动");
        Logger::close();
        return 0;
    }

    cout << "[步骤4/4] 启动虚拟局域网数据面..." << endl;
    Logger::info("[数据面] 启动 Wintun + 数据隧道主链路");

    std::unique_ptr<WintunManager> wintun_manager(new WintunManager());
    wstring wintun_error;
    if (!wintun_manager->Setup(lease_runtime, &wintun_error)) {
        string wintun_error_utf8 = wstring_to_utf8(wintun_error);
        Logger::error("[数据面] Wintun 初始化失败: " + wintun_error_utf8);
        cout << "错误: Wintun 初始化失败" << endl;
        cout << "  原因: " << wintun_error_utf8 << endl;
        Logger::close();
        MessageBoxW(NULL, (L"Wintun 初始化失败\n\n原因: " + wintun_error).c_str(), L"启动错误", MB_OK | MB_ICONERROR);
        return 1;
    }
    Logger::info("[数据面] Wintun运行时已就绪，尝试建立数据隧道专用会话");
    cout << "  ✓ Wintun运行时已就绪" << endl;

    std::unique_ptr<PacketTunnelClient> packet_tunnel_client(new PacketTunnelClient(
        TUNNEL_SERVER_IP,
        TUNNEL_PORT,
        g_session_uuid,
        lease_client_id,
        granted_lease.server_virtual_ip,
        granted_lease.virtual_ip,
        granted_lease.mtu,
        wintun_manager.get()));

    wstring packet_tunnel_error;
    if (!packet_tunnel_client->Start(&packet_tunnel_error)) {
        string packet_tunnel_error_utf8 = wstring_to_utf8(packet_tunnel_error);
        Logger::error("[数据面] 数据隧道专用会话建立失败: " + packet_tunnel_error_utf8);
        cout << "错误: 数据隧道专用会话建立失败" << endl;
        cout << "  原因: " << packet_tunnel_error_utf8 << endl;
        Logger::close();
        MessageBoxW(NULL, (L"数据隧道专用会话建立失败\n\n原因: " + packet_tunnel_error).c_str(), L"启动错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    wstring network_error;
    if (!wintun_manager->ActivateNetwork(lease_runtime, &network_error)) {
        string network_error_utf8 = wstring_to_utf8(network_error);
        Logger::error("[数据面] Wintun网络配置失败: " + network_error_utf8);
        packet_tunnel_client->Stop();
        cout << "错误: Wintun网络配置失败" << endl;
        cout << "  原因: " << network_error_utf8 << endl;
        Logger::close();
        MessageBoxW(NULL, (L"Wintun网络配置失败\n\n原因: " + network_error).c_str(), L"启动错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    Logger::info("[数据面] 数据隧道专用会话已建立，主链路切换到Wintun");
    cout << "  ✓ 数据隧道专用会话已建立" << endl;
    cout << endl;

    cout << "============================================================" << endl;
    cout << "✓ 系统就绪！当前运行在 Wintun + 数据隧道虚拟局域网链路" << endl;
    cout << "当前版本 " << VERSION_NAME << endl;
    cout << "============================================================" << endl;
    cout << endl;
    cout << "按Ctrl+C退出..." << endl;

    g_active_packet_tunnel = packet_tunnel_client.get();
    g_active_lease_session = &lease_session;
    SetConsoleCtrlHandler(ClientConsoleCtrlHandler, TRUE);

    int reconnect_attempt = 0;
    while (!g_shutdown_requested) {
        if (packet_tunnel_client->IsConnected()) {
            Sleep(200);
            reconnect_attempt = 0;
            continue;
        }

        if (g_shutdown_requested) {
            break;
        }

        g_active_packet_tunnel = nullptr;
        packet_tunnel_client->Stop();

        ++reconnect_attempt;
        Logger::warning("[数据面] 数据隧道连接已断开，开始自动重连，第" + to_string(reconnect_attempt) + "次");

        ip_tunnel::LeaseGrant recovered_lease;
        wstring recover_error;
        if (!lease_session.RecoverLease(&recovered_lease, recover_error)) {
            Logger::warning("[租约] 自动恢复失败: " + wstring_to_utf8(recover_error));
            Sleep(2000);
            continue;
        }

        lease_runtime = BuildLeaseRuntimeConfig(recovered_lease);
        wstring recover_network_error;
        if (!wintun_manager->ActivateNetwork(lease_runtime, &recover_network_error)) {
            Logger::warning("[数据面] 重连时应用Wintun网络配置失败: " + wstring_to_utf8(recover_network_error));
            Sleep(2000);
            continue;
        }

        packet_tunnel_client.reset(new PacketTunnelClient(
            TUNNEL_SERVER_IP,
            TUNNEL_PORT,
            g_session_uuid,
            lease_client_id,
            recovered_lease.server_virtual_ip,
            recovered_lease.virtual_ip,
            recovered_lease.mtu,
            wintun_manager.get()));

        wstring reconnect_error;
        if (!packet_tunnel_client->Start(&reconnect_error)) {
            Logger::warning("[数据面] 自动重连失败: " + wstring_to_utf8(reconnect_error));
            Sleep(2000);
            continue;
        }

        g_active_packet_tunnel = packet_tunnel_client.get();
        Logger::info("[数据面] 自动重连成功，虚拟IP=" + recovered_lease.virtual_ip);
    }

    g_active_packet_tunnel = nullptr;
    packet_tunnel_client->Stop();

    if (g_shutdown_requested) {
        for (int i = 0; i < 60 && !g_shutdown_completed; ++i) {
            Sleep(100);
        }
    }

    SetConsoleCtrlHandler(ClientConsoleCtrlHandler, FALSE);
    g_active_packet_tunnel = nullptr;
    g_active_lease_session = nullptr;
    g_shutdown_requested = false;
    g_shutdown_completed = false;
    Logger::close();
    return 0;
}
