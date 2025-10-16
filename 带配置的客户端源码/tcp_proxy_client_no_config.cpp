/*
 * DNF游戏代理客户端 - C++ 版本 v12.0 (虚拟网卡自动配置)
 * 从自身exe末尾读取配置
 *
 * v12.0更新: 虚拟网卡自动配置 ⭐ 最终完善版本
 *            新增功能: 程序启动时自动检测和配置虚拟网卡
 *                     1. 自动检测虚拟网卡是否已安装
 *                     2. 未安装时显示详细的手动安装指南
 *                     3. 自动配置双IP地址(192.168.2.106 + 192.168.2.200)
 *                     4. 自动查询并设置IfIdx
 *                     5. 所有步骤写入日志，方便调试
 *            使用方法: 直接运行，程序会引导完成所有配置
 *
 * v11.0更新: 虚拟网卡双IP方案 ⭐ 最终解决方案
 *            问题根源: 游戏同时验证3个条件：
 *                     1. UDP源IP必须在本机网卡上（Windows限制）
 *                     2. UDP源IP = 游戏服务器IP（192.168.2.106）
 *                     3. payload中的客户端IP也必须在本机网卡上，且 ≠ 服务器IP
 *            v10.0失败原因: payload IP（外网用户真实IP）不在本机任何网卡上
 *            解决方案: 虚拟网卡配置两个IP地址
 *                     - 主IP: 192.168.2.106（游戏服务器IP，用作UDP源IP）
 *                     - 辅助IP: 192.168.2.200（虚拟客户端IP，用于payload）
 *
 * v10.0更新: 虚拟网卡单IP方案（外网用户失败，payload IP验证不通过）
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>  // 用于GetAdaptersAddresses获取网络接口IPv4地址

// 重要：先包含 windivert.h 定义类型，但不导入函数
#define WINDIVERTEXPORT
#include "windivert.h"

// 然后包含动态加载器
#include "windivert_loader.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")  // 用于GetAdaptersAddresses
#pragma comment(lib, "setupapi.lib")  // 用于虚拟网卡安装
#pragma comment(lib, "newdev.lib")    // 用于DiInstallDriver
#pragma comment(lib, "cfgmgr32.lib")  // 用于设备管理

// 注意: 不再静态链接 WinDivert.lib，改用动态加载（windivert_loader.h）
// 这样程序启动时不会检查 WinDivert.dll 依赖，给自解压代码释放文件的机会

// 虚拟网卡安装需要的头文件
#include <setupapi.h>
#include <newdev.h>
#include <devguid.h>
#include <regstr.h>
#include <cfgmgr32.h>

// 定义硬件ID常量
#define HARDWARE_ID L"*msloop\0\0"
#define HARDWARE_ID_LEN 9

// 包含嵌入式 WinDivert 文件
#include "embedded_windivert.h"

using namespace std;

// ==================== v12.0 虚拟网卡自动配置 ====================
// 用于解决跨子网UDP源IP验证问题
// v12.0: 自动检测并配置虚拟网卡，程序启动时自动设置此值
UINT32 g_loopback_adapter_ifidx = 0;  // 0 = 需要自动配置，非0 = 已配置的IfIdx

// 虚拟网卡配置常量
const char* LOOPBACK_ADAPTER_SUBNET = "255.255.255.0";        // 子网掩码

// 虚拟网卡配置函数声明（实现在Logger类之后）
bool install_loopback_adapter_auto();
bool auto_setup_loopback_adapter(const string& primary_ip, const string& secondary_ip);

// ==================== WinDivert 自动部署 ====================

// 获取 WinDivert 临时目录路径
string get_windivert_temp_dir() {
    char temp_path[MAX_PATH];
    if (GetTempPathA(MAX_PATH, temp_path) == 0) {
        return "";
    }

    string windivert_dir = string(temp_path) + "WinDivert\\";

    // 创建 WinDivert 子目录（如果不存在）
    CreateDirectoryA(windivert_dir.c_str(), NULL);

    return windivert_dir;
}

// 释放嵌入资源到文件
bool extract_embedded_file(const string& filepath, const unsigned char* data, unsigned int size) {
    // 检查文件是否已存在且大小正确
    WIN32_FILE_ATTRIBUTE_DATA file_info;
    if (GetFileAttributesExA(filepath.c_str(), GetFileExInfoStandard, &file_info)) {
        ULONGLONG file_size = (ULONGLONG(file_info.nFileSizeHigh) << 32) | file_info.nFileSizeLow;
        if (file_size == size) {
            // 文件已存在且大小正确，跳过释放
            return true;
        }
    }

    // 释放文件
    ofstream file(filepath, ios::binary);
    if (!file.is_open()) {
        return false;
    }

    file.write((const char*)data, size);
    file.close();

    return true;
}

// 自动部署 WinDivert 文件
bool deploy_windivert_files(string& dll_path, string& sys_path) {
    // 获取临时目录
    string temp_dir = get_windivert_temp_dir();
    if (temp_dir.empty()) {
        cout << "错误: 无法获取临时目录" << endl;
        return false;
    }

    dll_path = temp_dir + "WinDivert.dll";
    sys_path = temp_dir + "WinDivert64.sys";

    cout << "WinDivert 临时目录: " << temp_dir << endl;

    // 释放 WinDivert.dll
    if (!extract_embedded_file(dll_path, EMBEDDED_WINDIVERT_DLL, EMBEDDED_WINDIVERT_DLL_SIZE)) {
        cout << "错误: 无法释放 WinDivert.dll" << endl;
        return false;
    }

    // 释放 WinDivert64.sys
    if (!extract_embedded_file(sys_path, EMBEDDED_WINDIVERT_SYS, EMBEDDED_WINDIVERT_SYS_SIZE)) {
        cout << "错误: 无法释放 WinDivert64.sys" << endl;
        return false;
    }

    return true;
}

// ==================== 网络接口工具 ====================

// 根据socket获取其使用的网络接口的IPv4地址
// sock: 已连接的socket (可以是IPv4或IPv6)
// 返回该socket所在网络接口的IPv4地址,如果无法获取则返回空字符串
string get_ipv4_from_socket_interface(SOCKET sock) {
    // 1. 获取socket的本地地址
    sockaddr_storage local_addr{};
    int addr_len = sizeof(local_addr);

    if (getsockname(sock, (sockaddr*)&local_addr, &addr_len) != 0) {
        return "";  // 获取本地地址失败
    }

    // 2. 提取接口索引
    DWORD interface_index = 0;

    if (local_addr.ss_family == AF_INET6) {
        // IPv6: 从sockaddr_in6获取接口索引
        sockaddr_in6* addr6 = (sockaddr_in6*)&local_addr;
        interface_index = addr6->sin6_scope_id;

        // 如果scope_id为0,尝试通过GetBestInterfaceEx获取
        if (interface_index == 0) {
            sockaddr_in6 dest_addr{};
            dest_addr.sin6_family = AF_INET6;
            // 使用连接的对端地址
            int peer_len = sizeof(dest_addr);
            if (getpeername(sock, (sockaddr*)&dest_addr, &peer_len) == 0) {
                GetBestInterfaceEx((sockaddr*)&dest_addr, &interface_index);
            }
        }
    } else if (local_addr.ss_family == AF_INET) {
        // IPv4: 使用GetBestInterfaceEx获取接口索引
        GetBestInterfaceEx((sockaddr*)&local_addr, &interface_index);
    }

    if (interface_index == 0) {
        return "";  // 无法确定接口索引
    }

    // 3. 获取所有网络适配器信息
    ULONG buffer_size = 15000;
    PIP_ADAPTER_ADDRESSES adapter_addresses = nullptr;
    ULONG result = 0;

    for (int attempts = 0; attempts < 3; attempts++) {
        adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(buffer_size);
        if (!adapter_addresses) {
            return "";
        }

        result = GetAdaptersAddresses(
            AF_UNSPEC,  // 获取IPv4和IPv6地址
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            adapter_addresses,
            &buffer_size
        );

        if (result == ERROR_SUCCESS) {
            break;
        }

        free(adapter_addresses);
        adapter_addresses = nullptr;

        if (result != ERROR_BUFFER_OVERFLOW) {
            return "";
        }
    }

    if (result != ERROR_SUCCESS || !adapter_addresses) {
        return "";
    }

    // 4. 在适配器列表中查找匹配的接口索引,并提取IPv4地址
    string ipv4_address;
    PIP_ADAPTER_ADDRESSES current = adapter_addresses;

    while (current) {
        // 检查接口索引是否匹配(IPv6接口索引)
        if (current->Ipv6IfIndex == interface_index || current->IfIndex == interface_index) {
            // 遍历该接口的所有单播地址,查找IPv4
            PIP_ADAPTER_UNICAST_ADDRESS unicast = current->FirstUnicastAddress;
            while (unicast) {
                if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* addr_in = (sockaddr_in*)unicast->Address.lpSockaddr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
                    string ipv4 = string(ip_str);

                    // 跳过环回地址 (127.x.x.x)
                    if (ipv4.find("127.") == 0) {
                        unicast = unicast->Next;
                        continue;
                    }

                    // 跳过链路本地地址 (169.254.x.x)
                    if (ipv4.find("169.254.") == 0) {
                        unicast = unicast->Next;
                        continue;
                    }

                    // 找到有效的IPv4地址
                    ipv4_address = ipv4;
                    break;
                }
                unicast = unicast->Next;
            }

            if (!ipv4_address.empty()) {
                break;  // 找到了就退出
            }
        }

        current = current->Next;
    }

    free(adapter_addresses);
    return ipv4_address;
}

// 通过Windows网络接口API获取本机的IPv4地址(用于启动时显示)
// 返回第一个有效的非环回、非链路本地的IPv4地址
string get_local_ipv4_address() {
    ULONG buffer_size = 15000;
    PIP_ADAPTER_ADDRESSES adapter_addresses = nullptr;
    ULONG result = 0;

    for (int attempts = 0; attempts < 3; attempts++) {
        adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(buffer_size);
        if (!adapter_addresses) {
            return "";
        }

        result = GetAdaptersAddresses(
            AF_INET,  // 只获取IPv4地址
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            adapter_addresses,
            &buffer_size
        );

        if (result == ERROR_SUCCESS) {
            break;
        }

        free(adapter_addresses);
        adapter_addresses = nullptr;

        if (result != ERROR_BUFFER_OVERFLOW) {
            return "";
        }
    }

    if (result != ERROR_SUCCESS || !adapter_addresses) {
        return "";
    }

    string best_ipv4;
    PIP_ADAPTER_ADDRESSES current_adapter = adapter_addresses;

    while (current_adapter) {
        if (current_adapter->OperStatus != IfOperStatusUp) {
            current_adapter = current_adapter->Next;
            continue;
        }

        PIP_ADAPTER_UNICAST_ADDRESS unicast = current_adapter->FirstUnicastAddress;
        while (unicast) {
            if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* addr_in = (sockaddr_in*)unicast->Address.lpSockaddr;
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
                string ipv4 = string(ip_str);

                if (ipv4.find("127.") == 0 || ipv4.find("169.254.") == 0) {
                    unicast = unicast->Next;
                    continue;
                }

                if (best_ipv4.empty()) {
                    best_ipv4 = ipv4;
                }
                else if (current_adapter->IfType == IF_TYPE_ETHERNET_CSMACD) {
                    best_ipv4 = ipv4;
                }
            }
            unicast = unicast->Next;
        }

        current_adapter = current_adapter->Next;
    }

    free(adapter_addresses);
    return best_ipv4;
}

// ==================== 配置读取 ====================

bool read_config_from_self(string& game_ip, string& tunnel_ip, int& port) {
    // 1. 获取当前exe路径
    char exe_path[MAX_PATH];
    if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) == 0) {
        return false;
    }

    // 2. 打开自身文件
    ifstream file(exe_path, ios::binary | ios::ate);
    if (!file.is_open()) {
        return false;
    }

    // 3. 获取文件大小
    streamsize file_size = file.tellg();
    if (file_size < 100) {
        file.close();
        return false;
    }

    // 4. 从末尾搜索配置标记
    const string END_MARKER = "[CONFIG_END]";
    const string START_MARKER = "[CONFIG_START]";
    const int SEARCH_BUFFER_SIZE = 8192;  // 搜索最后8KB

    // 读取文件末尾
    int search_size = min((streamsize)SEARCH_BUFFER_SIZE, file_size);
    vector<char> buffer(search_size);
    file.seekg(file_size - search_size, ios::beg);
    file.read(buffer.data(), search_size);
    file.close();

    string tail_content(buffer.data(), search_size);

    // 5. 查找标记
    size_t end_pos = tail_content.rfind(END_MARKER);
    if (end_pos == string::npos) {
        return false;
    }

    size_t start_pos = tail_content.rfind(START_MARKER, end_pos);
    if (start_pos == string::npos) {
        return false;
    }

    // 6. 提取JSON
    start_pos += START_MARKER.length();
    if (start_pos >= end_pos) {
        return false;
    }

    string json_content = tail_content.substr(start_pos, end_pos - start_pos);

    // 7. 简单解析JSON (不使用外部库)
    // 期望格式: {"game_server_ip":"192.168.1.100","tunnel_server_ip":"10.0.0.50","tunnel_port":33223}

    // 查找game_server_ip
    size_t game_ip_pos = json_content.find("\"game_server_ip\"");
    if (game_ip_pos == string::npos) return false;
    size_t game_ip_colon = json_content.find(":", game_ip_pos);
    if (game_ip_colon == string::npos) return false;
    size_t game_ip_quote1 = json_content.find("\"", game_ip_colon);
    if (game_ip_quote1 == string::npos) return false;
    size_t game_ip_quote2 = json_content.find("\"", game_ip_quote1 + 1);
    if (game_ip_quote2 == string::npos) return false;
    game_ip = json_content.substr(game_ip_quote1 + 1, game_ip_quote2 - game_ip_quote1 - 1);

    // 查找tunnel_server_ip
    size_t tunnel_ip_pos = json_content.find("\"tunnel_server_ip\"");
    if (tunnel_ip_pos == string::npos) return false;
    size_t tunnel_ip_colon = json_content.find(":", tunnel_ip_pos);
    if (tunnel_ip_colon == string::npos) return false;
    size_t tunnel_ip_quote1 = json_content.find("\"", tunnel_ip_colon);
    if (tunnel_ip_quote1 == string::npos) return false;
    size_t tunnel_ip_quote2 = json_content.find("\"", tunnel_ip_quote1 + 1);
    if (tunnel_ip_quote2 == string::npos) return false;
    tunnel_ip = json_content.substr(tunnel_ip_quote1 + 1, tunnel_ip_quote2 - tunnel_ip_quote1 - 1);

    // 查找tunnel_port
    size_t port_pos = json_content.find("\"tunnel_port\"");
    if (port_pos == string::npos) return false;
    size_t port_colon = json_content.find(":", port_pos);
    if (port_colon == string::npos) return false;
    size_t port_comma = json_content.find_first_of(",}", port_colon);
    if (port_comma == string::npos) return false;

    string port_str = json_content.substr(port_colon + 1, port_comma - port_colon - 1);
    // 去除空格
    port_str.erase(remove_if(port_str.begin(), port_str.end(), ::isspace), port_str.end());

    try {
        port = stoi(port_str);
    } catch (...) {
        return false;
    }

    return true;
}

// ==================== 日志工具 ====================

class Logger {
private:
    static ofstream log_file;
    static bool file_enabled;
    static string current_log_level;

public:
    static void set_log_level(const string& level) {
        current_log_level = level;
    }

    static void init(const string& filename) {
        log_file.open(filename, ios::out | ios::app);
        if (log_file.is_open()) {
            file_enabled = true;
            // 直接输出不调用log避免问题
            SYSTEMTIME st;
            GetLocalTime(&st);
            char log_line[512];
            sprintf(log_line, "%04d-%02d-%02d %02d:%02d:%02d.%03d [INFO] 日志文件已初始化: %s\n",
                   st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                   filename.c_str());
            printf("%s", log_line);
            log_file << log_line;
            log_file.flush();
        }
    }

    static void close() {
        if (log_file.is_open()) {
            log_file.close();
            file_enabled = false;
        }
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
        // 日志级别过滤: ERROR(3) > WARN(2) > INFO(1) > DEBUG(0)
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

        // 如果当前日志级别低于设定级别，不输出
        if (level_priority < current_priority) return;

        SYSTEMTIME st;
        GetLocalTime(&st);
        char log_line[65536];  // 大缓冲区用于长日志
        sprintf(log_line, "%04d-%02d-%02d %02d:%02d:%02d.%03d [%s] %s\n",
               st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
               level.c_str(), msg.c_str());

        printf("%s", log_line);
        fflush(stdout);

        if (file_enabled && log_file.is_open()) {
            log_file << log_line;
            log_file.flush();
        }
    }
};

// 静态成员初始化
ofstream Logger::log_file;
bool Logger::file_enabled = false;
string Logger::current_log_level = "INFO";

// ==================== 启动握手测试 ====================
// 在程序启动时主动连接隧道服务器进行握手测试
// 目的：预热整个代理链路，避免第一次连接失败
bool test_tunnel_handshake(const string& tunnel_ip, uint16_t tunnel_port) {
    cout << "[启动测试] 正在测试到隧道服务器的连接..." << endl;
    Logger::info("[启动测试] 开始握手测试 -> " + tunnel_ip + ":" + to_string(tunnel_port));

    // 使用getaddrinfo支持域名/IPv4/IPv6
    struct addrinfo hints{}, *result = nullptr, *rp = nullptr;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      // 允许IPv4或IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP
    hints.ai_protocol = IPPROTO_TCP;

    string port_str = to_string(tunnel_port);
    int ret = getaddrinfo(tunnel_ip.c_str(), port_str.c_str(), &hints, &result);
    if (ret != 0) {
        cout << "[启动测试] ✗ DNS解析失败: " << tunnel_ip << endl;
        Logger::error("[启动测试] DNS解析失败: " + tunnel_ip + " (错误: " + to_string(ret) + ")");
        return false;
    }

    // 尝试连接所有解析结果
    SOCKET test_sock = INVALID_SOCKET;
    bool connected = false;

    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        test_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (test_sock == INVALID_SOCKET) {
            continue;
        }

        Logger::debug("[启动测试] 尝试连接 (协议: " +
                     string(rp->ai_family == AF_INET ? "IPv4" : "IPv6") + ")");

        // 设置连接超时
        DWORD timeout = 5000;  // 5秒超时
        setsockopt(test_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(test_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        if (connect(test_sock, rp->ai_addr, (int)rp->ai_addrlen) != SOCKET_ERROR) {
            connected = true;
            Logger::debug("[启动测试] 连接成功");
            break;
        }

        Logger::debug("[启动测试] 连接失败，尝试下一个地址");
        closesocket(test_sock);
        test_sock = INVALID_SOCKET;
    }

    freeaddrinfo(result);

    if (!connected || test_sock == INVALID_SOCKET) {
        cout << "[启动测试] ✗ 无法连接到隧道服务器" << endl;
        Logger::error("[启动测试] 所有连接尝试均失败");
        return false;
    }

    // 发送测试握手包: conn_id(4)=0 + dst_port(2)=65535 (特殊标记表示测试连接)
    uint8_t handshake[6];
    *(uint32_t*)handshake = htonl(0);      // conn_id=0 表示测试
    *(uint16_t*)(handshake + 4) = htons(65535);  // port=65535 表示测试

    if (send(test_sock, (char*)handshake, 6, 0) != 6) {
        cout << "[启动测试] ✗ 发送测试握手失败" << endl;
        Logger::error("[启动测试] 发送握手包失败");
        closesocket(test_sock);
        return false;
    }

    Logger::debug("[启动测试] 已发送测试握手包");

    // 等待服务器响应（或超时）
    // 服务器可能会发送确认或直接关闭连接，两种情况都算成功
    uint8_t response[64];
    int recv_len = recv(test_sock, (char*)response, sizeof(response), 0);

    closesocket(test_sock);

    if (recv_len > 0) {
        cout << "[启动测试] ✓ 隧道服务器响应正常 (收到 " << recv_len << " 字节)" << endl;
        Logger::info("[启动测试] 收到服务器响应: " + to_string(recv_len) + "字节");
    } else if (recv_len == 0) {
        // 服务器关闭连接，这也是正常的（说明连接建立成功）
        cout << "[启动测试] ✓ 隧道服务器连接正常 (连接已建立)" << endl;
        Logger::info("[启动测试] 服务器接受连接并关闭");
    } else {
        // 超时或错误，但连接已建立，仍然算成功
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT) {
            cout << "[启动测试] ✓ 隧道服务器连接正常 (超时，但连接已建立)" << endl;
            Logger::info("[启动测试] 接收超时，但TCP连接已成功建立");
        } else {
            cout << "[启动测试] ⚠ 连接已建立，但接收时出错 (错误码: " << err << ")" << endl;
            Logger::warning("[启动测试] 接收错误: " + to_string(err) + "，但连接已建立");
        }
    }

    Logger::info("[启动测试] ========================================");
    Logger::info("[启动测试] 握手测试完成，代理链路就绪");
    Logger::info("[启动测试] ========================================");

    return true;
}

// ==================== IP地址计算工具 ====================

// 计算辅助IP（同网段的.252，避免与用户网络冲突）
string calculate_secondary_ip(const string& primary_ip) {
    size_t last_dot = primary_ip.rfind('.');
    if (last_dot == string::npos) {
        Logger::error("[IP计算] 无法解析主IP地址: " + primary_ip);
        return "";
    }

    // 提取网络前缀 (xxx.xxx.xxx)
    string network_prefix = primary_ip.substr(0, last_dot);

    // 拼接 .252
    string secondary_ip = network_prefix + ".252";

    Logger::info("[IP计算] 主IP: " + primary_ip + " → 辅助IP: " + secondary_ip);
    cout << "[IP计算] 辅助IP: " + secondary_ip + " (虚拟客户端IP)" << endl;

    return secondary_ip;
}

// ==================== 虚拟网卡自动配置函数实现 ====================

// 完全自动安装Microsoft Loopback Adapter（适配所有Windows系统）
bool install_loopback_adapter_auto() {
    Logger::info("[自动安装] 开始安装虚拟网卡");
    cout << "正在自动安装 Microsoft Loopback Adapter..." << endl;

    // 方法1: 使用SetupAPI创建虚拟设备（适用于所有Windows版本）
    Logger::info("[自动安装] 方法1: 使用SetupAPI");
    cout << "  [方法1] 使用 SetupAPI 创建设备..." << endl;

    HDEVINFO device_info_set = SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, NULL);
    if (device_info_set == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        Logger::error("[自动安装] SetupDiCreateDeviceInfoList 失败，错误码: " + to_string(error));
        cout << "    失败：无法创建设备信息集 (错误码: " << error << ")" << endl;
        return false;
    }

    SP_DEVINFO_DATA device_info_data;
    device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

    // 创建设备信息（使用中文名称）
    if (!SetupDiCreateDeviceInfoW(device_info_set, L"ms_loopback", &GUID_DEVCLASS_NET,
                                   L"Microsoft KM-TEST 环回适配器", NULL,
                                   DICD_GENERATE_ID, &device_info_data)) {
        DWORD error = GetLastError();
        Logger::error("[自动安装] SetupDiCreateDeviceInfo 失败，错误码: " + to_string(error));
        cout << "    失败：无法创建设备信息 (错误码: " << error << ")" << endl;
        SetupDiDestroyDeviceInfoList(device_info_set);
        return false;
    }

    // 设置硬件ID
    if (!SetupDiSetDeviceRegistryPropertyW(device_info_set, &device_info_data,
                                           SPDRP_HARDWAREID, (BYTE*)HARDWARE_ID,
                                           HARDWARE_ID_LEN * sizeof(WCHAR))) {
        DWORD error = GetLastError();
        Logger::error("[自动安装] SetupDiSetDeviceRegistryProperty 失败，错误码: " + to_string(error));
        cout << "    失败：无法设置硬件ID (错误码: " << error << ")" << endl;
        SetupDiDestroyDeviceInfoList(device_info_set);
        return false;
    }

    // 注册设备
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, device_info_set, &device_info_data)) {
        DWORD error = GetLastError();
        Logger::error("[自动安装] SetupDiCallClassInstaller(DIF_REGISTERDEVICE) 失败，错误码: " + to_string(error));
        cout << "    失败：无法注册设备 (错误码: " << error << ")" << endl;
        SetupDiDestroyDeviceInfoList(device_info_set);
        return false;
    }

    cout << "    ✓ 设备已注册" << endl;
    Logger::info("[自动安装] 设备已注册");

    // 安装驱动
    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, device_info_set, &device_info_data)) {
        DWORD error = GetLastError();
        Logger::error("[自动安装] SetupDiCallClassInstaller(DIF_INSTALLDEVICE) 失败，错误码: " + to_string(error));
        cout << "    失败：驱动安装失败 (错误码: " << error << ")" << endl;

        // 注意：不清理设备，保留已注册的设备给方法2使用
        Logger::info("[自动安装] 保留已注册的设备，尝试其他安装方法");
        SetupDiDestroyDeviceInfoList(device_info_set);

        // 尝试方法2
        goto method2;
    }

    cout << "    ✓ 驱动已安装" << endl;
    Logger::info("[自动安装] 驱动安装成功");
    SetupDiDestroyDeviceInfoList(device_info_set);

    // 等待设备初始化
    cout << "  等待设备初始化..." << endl;
    Sleep(3000);

    return true;

method2:
    // 方法2: 使用UpdateDriverForPlugAndPlayDevices API（推荐）
    Logger::info("[自动安装] 方法2: 使用UpdateDriverForPlugAndPlayDevices");
    cout << "  [方法2] 使用驱动更新API安装..." << endl;

    // 加载newdev.dll
    typedef BOOL (WINAPI *UpdateDriverForPlugAndPlayDevicesW_t)(
        HWND hwndParent,
        LPCWSTR HardwareId,
        LPCWSTR FullInfPath,
        DWORD InstallFlags,
        PBOOL bRebootRequired
    );

    HMODULE newdev = LoadLibraryA("newdev.dll");
    if (newdev) {
        UpdateDriverForPlugAndPlayDevicesW_t UpdateDriverFunc =
            (UpdateDriverForPlugAndPlayDevicesW_t)GetProcAddress(newdev, "UpdateDriverForPlugAndPlayDevicesW");

        if (UpdateDriverFunc) {
            BOOL reboot_required = FALSE;
            // 使用系统内置的netloop.inf
            wchar_t inf_path[MAX_PATH];
            GetWindowsDirectoryW(inf_path, MAX_PATH);
            wcscat(inf_path, L"\\inf\\netloop.inf");

            Logger::info("[自动安装] 调用UpdateDriverForPlugAndPlayDevices");
            cout << "    安装驱动..." << endl;

            if (UpdateDriverFunc(NULL, L"*msloop", inf_path,
                                INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE,
                                &reboot_required)) {
                cout << "    ✓ 驱动安装成功" << endl;
                Logger::info("[自动安装] 方法2成功");
                FreeLibrary(newdev);
                Sleep(3000);
                return true;
            } else {
                DWORD error = GetLastError();
                Logger::error("[自动安装] UpdateDriverForPlugAndPlayDevices 失败，错误码: " + to_string(error));
                cout << "    失败 (错误码: " << error << ")" << endl;
            }
        }
        FreeLibrary(newdev);
    }

    // 方法3: 使用pnputil命令（Windows Vista+）
    cout << "  [方法3] 使用pnputil命令..." << endl;
    Logger::info("[自动安装] 方法3: 使用pnputil");

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    // 先添加驱动包
    string cmd = "pnputil /add-driver %windir%\\inf\\netloop.inf /install";
    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        DWORD exit_code;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (exit_code == 0) {
            cout << "    ✓ pnputil安装成功" << endl;
            Logger::info("[自动安装] 方法3成功");
            Sleep(3000);
            return true;
        } else {
            Logger::error("[自动安装] pnputil失败，退出码: " + to_string(exit_code));
        }
    }

    // 方法4: 使用PowerShell（Windows 7+）
    cout << "  [方法4] 使用PowerShell脚本..." << endl;
    Logger::info("[自动安装] 方法4: 使用PowerShell");

    cmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"Add-WindowsDriver -Online -Driver $env:windir\\inf\\netloop.inf\"";
    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 20000);
        DWORD exit_code;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (exit_code == 0) {
            cout << "    ✓ PowerShell安装成功" << endl;
            Logger::info("[自动安装] 方法4成功");
            Sleep(3000);
            return true;
        }
    }

    Logger::error("[自动安装] 所有自动安装方法均失败");
    cout << "  ✗ 自动安装失败" << endl;
    return false;
}

// 执行命令并捕获输出（增强稳定性）
string execute_command(const string& command) {
    string result;
    try {
        char buffer[256];
        FILE* pipe = _popen(command.c_str(), "r");
        if (!pipe) {
            Logger::error("[命令执行] _popen失败: " + command);
            return "";
        }

        // 读取输出，限制最大大小防止崩溃
        int total_read = 0;
        const int MAX_OUTPUT = 4096;

        while (fgets(buffer, sizeof(buffer), pipe) != nullptr && total_read < MAX_OUTPUT) {
            result += buffer;
            total_read += strlen(buffer);
        }

        int close_result = _pclose(pipe);
        if (close_result != 0) {
            Logger::error("[命令执行] 命令执行失败，退出码: " + to_string(close_result));
        }
    } catch (...) {
        Logger::error("[命令执行] 捕获异常: " + command);
        return "";
    }
    return result;
}

// 查找虚拟网卡名称（支持通过主IP查找）
string find_loopback_adapter_name(const string& primary_ip = "") {
    ULONG buffer_size = 15000;
    PIP_ADAPTER_ADDRESSES adapter_addresses = nullptr;

    for (int attempts = 0; attempts < 3; attempts++) {
        adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(buffer_size);
        if (!adapter_addresses) {
            return "";
        }

        ULONG result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapter_addresses, &buffer_size);

        if (result == ERROR_SUCCESS) {
            break;
        }

        free(adapter_addresses);
        adapter_addresses = nullptr;

        if (result != ERROR_BUFFER_OVERFLOW) {
            return "";
        }
    }

    if (!adapter_addresses) {
        return "";
    }

    string adapter_name;

    // 遍历所有网卡
    for (PIP_ADAPTER_ADDRESSES adapter = adapter_addresses; adapter != nullptr; adapter = adapter->Next) {
        // 检查是否是Microsoft Loopback Adapter（支持中英文）
        bool is_loopback = false;

        // 方法1: 检查是否包含 "KM-TEST"（中英文通用）
        if (wcsstr(adapter->Description, L"KM-TEST")) {
            is_loopback = true;
        }
        // 方法2: 检查英文 "Microsoft" + "Loopback"
        else if (wcsstr(adapter->Description, L"Microsoft") && wcsstr(adapter->Description, L"Loopback")) {
            is_loopback = true;
        }
        // 方法3: 检查中文 "环回适配器" 或 "回环适配器"
        else if (wcsstr(adapter->Description, L"环回") || wcsstr(adapter->Description, L"回环")) {
            is_loopback = true;
        }

        if (is_loopback) {
            char friendly_name[256] = {0};
            WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, friendly_name, sizeof(friendly_name), NULL, NULL);
            adapter_name = friendly_name;
            break;
        }

        // 或者检查是否配置了主IP（如果提供了primary_ip参数）
        if (!primary_ip.empty()) {
            for (PIP_ADAPTER_UNICAST_ADDRESS addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next) {
                if (addr->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* addr_in = (sockaddr_in*)addr->Address.lpSockaddr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);

                    if (strcmp(ip_str, primary_ip.c_str()) == 0) {
                        char friendly_name[256] = {0};
                        WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, friendly_name, sizeof(friendly_name), NULL, NULL);
                        adapter_name = friendly_name;
                        break;
                    }
                }
            }
        }

        if (!adapter_name.empty()) {
            break;
        }
    }

    free(adapter_addresses);
    return adapter_name;
}

// 检查IP是否已配置（使用Windows API，不依赖命令行）
bool check_ip_configured(const string& adapter_name, const char* ip) {
    ULONG buffer_size = 15000;
    PIP_ADAPTER_ADDRESSES adapter_addresses = nullptr;

    for (int attempts = 0; attempts < 3; attempts++) {
        adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(buffer_size);
        if (!adapter_addresses) {
            return false;
        }

        ULONG result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr,
                                           adapter_addresses, &buffer_size);

        if (result == ERROR_SUCCESS) {
            break;
        }

        free(adapter_addresses);
        adapter_addresses = nullptr;

        if (result != ERROR_BUFFER_OVERFLOW) {
            return false;
        }
    }

    if (!adapter_addresses) {
        return false;
    }

    bool found = false;

    // 遍历所有网卡，找到匹配的网卡名称
    for (PIP_ADAPTER_ADDRESSES adapter = adapter_addresses; adapter != nullptr; adapter = adapter->Next) {
        char friendly_name[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, friendly_name, sizeof(friendly_name), NULL, NULL);

        if (strcmp(friendly_name, adapter_name.c_str()) == 0) {
            // 检查这个网卡上是否有指定的IP
            for (PIP_ADAPTER_UNICAST_ADDRESS addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next) {
                if (addr->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* addr_in = (sockaddr_in*)addr->Address.lpSockaddr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);

                    if (strcmp(ip_str, ip) == 0) {
                        found = true;
                        break;
                    }
                }
            }
            break;
        }
    }

    free(adapter_addresses);
    return found;
}

// 配置IP地址（主IP + 辅助IP）
bool configure_loopback_ips(const string& adapter_name, const string& primary_ip, const string& secondary_ip) {
    try {
        cout << "正在配置虚拟网卡IP地址..." << endl;
        Logger::info("[IP配置] 开始配置，网卡: " + adapter_name);
        Logger::info("[IP配置] 主IP: " + primary_ip + ", 辅助IP: " + secondary_ip);

        // 检查IP是否已配置
        Logger::info("[IP配置] 检查当前IP配置");
        bool primary_configured = check_ip_configured(adapter_name, primary_ip.c_str());
        Logger::info("[IP配置] 主IP检查完成: " + string(primary_configured ? "已配置" : "未配置"));

        bool secondary_configured = check_ip_configured(adapter_name, secondary_ip.c_str());
        Logger::info("[IP配置] 辅助IP检查完成: " + string(secondary_configured ? "已配置" : "未配置"));

    if (primary_configured && secondary_configured) {
        cout << "  IP地址已正确配置" << endl;
        Logger::info("[IP配置] IP已配置，跳过");
        return true;
    }

    // 使用PowerShell WMI方法配置双IP（更可靠）
    if (!primary_configured || !secondary_configured) {
        cout << "  使用PowerShell配置双IP..." << endl;
        Logger::info("[IP配置] 使用PowerShell WMI方法配置双IP");

        // 构建PowerShell命令：配置双IP地址（使用动态IP）
        string ps_command = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"";
        ps_command += "$adapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.Description -like '*KM-TEST*' -or $_.Description -like '*环回*'}; ";
        ps_command += "if ($adapter) { ";
        ps_command += "$result = $adapter.EnableStatic(@('" + primary_ip + "', '" + secondary_ip + "'), @('" + string(LOOPBACK_ADAPTER_SUBNET) + "', '" + string(LOOPBACK_ADAPTER_SUBNET) + "')); ";
        ps_command += "if ($result.ReturnValue -eq 0) { Write-Host 'SUCCESS' } else { exit 1 } ";
        ps_command += "} else { exit 2 }\"";

        Logger::info("[IP配置] PowerShell命令: " + ps_command);

        bool success = false;
        for (int retry = 0; retry < 3 && !success; retry++) {
            if (retry > 0) {
                cout << "    重试 " << retry << "/3..." << endl;
                Logger::info("[IP配置] 重试PowerShell配置，第" + to_string(retry) + "次");
                Sleep(3000);  // 等待网卡初始化
            }

            int result = system(ps_command.c_str());
            Logger::info("[IP配置] PowerShell命令执行结果: " + to_string(result));

            if (result == 0) {
                success = true;
                cout << "  ✓ PowerShell配置成功" << endl;
                Sleep(2000);  // 等待配置生效
            }
        }

        if (!success) {
            Logger::error("[IP配置] PowerShell配置失败");
            cout << "  ⚠ PowerShell配置失败，尝试备用方案..." << endl;

            // 备用方案：使用netsh逐个配置（使用动态IP）
            cout << "  使用netsh配置主IP..." << endl;
            string cmd1 = "netsh interface ip set address \"" + adapter_name + "\" static " +
                         primary_ip + " " + string(LOOPBACK_ADAPTER_SUBNET);
            system(cmd1.c_str());
            Sleep(2000);

            cout << "  使用netsh添加辅助IP..." << endl;
            string cmd2 = "netsh interface ip add address \"" + adapter_name + "\" " +
                         secondary_ip + " " + string(LOOPBACK_ADAPTER_SUBNET);
            system(cmd2.c_str());
            Sleep(2000);
        }
    }

    // 验证配置
    Sleep(2000);  // 给配置更多时间生效
    primary_configured = check_ip_configured(adapter_name, primary_ip.c_str());
    secondary_configured = check_ip_configured(adapter_name, secondary_ip.c_str());

        if (primary_configured && secondary_configured) {
            cout << "  ✓ IP地址配置成功" << endl;
            Logger::info("[IP配置] ✓ 配置成功");
            return true;
        } else {
            cout << "  ⚠ IP地址自动配置失败" << endl;
            Logger::error("[IP配置] ✗ 自动配置失败");
            cout << endl;
            cout << "========================================" << endl;
            cout << "需要手动配置IP地址" << endl;
            cout << "========================================" << endl;
            cout << endl;
            cout << "请按以下步骤操作：" << endl;
            cout << "1. 打开 控制面板 → 网络和Internet → 网络连接" << endl;
            cout << "2. 找到\"" << adapter_name << "\"，右键 → 属性" << endl;
            cout << "3. 双击\"Internet 协议版本4 (TCP/IPv4)\"" << endl;
            cout << "4. 选择\"使用下面的IP地址\"" << endl;
            cout << "5. 输入以下信息：" << endl;
            cout << "   IP地址: " << primary_ip << endl;
            cout << "   子网掩码: " << LOOPBACK_ADAPTER_SUBNET << endl;
            cout << "6. 点击\"高级\"按钮" << endl;
            cout << "7. 在\"IP地址\"下点击\"添加\"" << endl;
            cout << "8. 添加第二个IP：" << secondary_ip << endl;
            cout << "   子网掩码: " << LOOPBACK_ADAPTER_SUBNET << endl;
            cout << "9. 点击\"确定\"保存配置" << endl;
            cout << endl;
            cout << "配置完成后，按任意键继续..." << endl;
            cout << "========================================" << endl;
            system("pause");
            cout << endl;

            // 重新验证
            cout << "  重新检测IP配置..." << endl;
            primary_configured = check_ip_configured(adapter_name, primary_ip.c_str());
            secondary_configured = check_ip_configured(adapter_name, secondary_ip.c_str());

            if (primary_configured && secondary_configured) {
                cout << "  ✓ 检测到IP配置成功" << endl;
                Logger::info("[IP配置] ✓ 手动配置成功");
                return true;
            } else {
                cout << "  ✗ 仍未检测到正确的IP配置" << endl;
                Logger::error("[IP配置] ✗ 手动配置也失败");
                return false;
            }
        }
    } catch (const exception& e) {
        Logger::error("[IP配置] 捕获异常: " + string(e.what()));
        cout << "  ✗ IP配置过程中发生异常" << endl;
        return false;
    } catch (...) {
        Logger::error("[IP配置] 捕获未知异常");
        cout << "  ✗ IP配置过程中发生未知异常" << endl;
        return false;
    }
}

// 查询虚拟网卡的IfIdx
UINT32 query_loopback_ifidx(const string& adapter_name) {
    ULONG buffer_size = 15000;
    PIP_ADAPTER_ADDRESSES adapter_addresses = nullptr;

    for (int attempts = 0; attempts < 3; attempts++) {
        adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(buffer_size);
        if (!adapter_addresses) {
            return 0;
        }

        ULONG result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapter_addresses, &buffer_size);

        if (result == ERROR_SUCCESS) {
            break;
        }

        free(adapter_addresses);
        adapter_addresses = nullptr;

        if (result != ERROR_BUFFER_OVERFLOW) {
            return 0;
        }
    }

    if (!adapter_addresses) {
        return 0;
    }

    UINT32 ifidx = 0;

    for (PIP_ADAPTER_ADDRESSES adapter = adapter_addresses; adapter != nullptr; adapter = adapter->Next) {
        char friendly_name[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, friendly_name, sizeof(friendly_name), NULL, NULL);

        if (strcmp(friendly_name, adapter_name.c_str()) == 0) {
            ifidx = adapter->IfIndex;
            break;
        }
    }

    free(adapter_addresses);
    return ifidx;
}

// 主配置函数：自动设置虚拟网卡（v12.1.0 支持动态IP）
bool auto_setup_loopback_adapter(const string& primary_ip, const string& secondary_ip) {
    cout << "========================================" << endl;
    cout << "虚拟网卡自动配置 (v12.1.0)" << endl;
    cout << "========================================" << endl;
    cout << endl;

    Logger::info("========================================");
    Logger::info("虚拟网卡自动配置 (v12.1.0)");
    Logger::info("  主IP（游戏服务器）: " + primary_ip);
    Logger::info("  辅助IP（虚拟客户端）: " + secondary_ip);
    Logger::info("========================================");

    // 1. 查找虚拟网卡
    cout << "[1/3] 检测虚拟网卡..." << endl;
    Logger::info("[1/3] 检测虚拟网卡");
    string adapter_name = find_loopback_adapter_name(primary_ip);

    if (adapter_name.empty()) {
        cout << "  未找到虚拟网卡，开始自动安装..." << endl;
        Logger::info("[1/3] 未找到虚拟网卡，开始自动安装");
        cout << endl;

        // 调用自动安装函数
        if (!install_loopback_adapter_auto()) {
            cout << endl;
            cout << "========================================" << endl;
            cout << "自动安装失败，请手动安装" << endl;
            cout << "========================================" << endl;
            cout << endl;
            cout << "手动安装步骤（只需30秒）：" << endl;
            cout << "1. 按 Win+X，选择 \"设备管理器\"" << endl;
            cout << "2. 点击顶部菜单 \"操作\" → \"添加过时硬件\"" << endl;
            cout << "3. 选择 \"安装我手动从列表选择的硬件\"" << endl;
            cout << "4. 类别选择 \"网络适配器\"" << endl;
            cout << "5. 厂商选择 \"Microsoft\"" << endl;
            cout << "6. 型号选择 \"Microsoft KM-TEST 环回适配器\"" << endl;
            cout << "   (英文系统为 \"Microsoft KM-TEST Loopback Adapter\")" << endl;
            cout << "7. 点击 \"下一步\" 完成安装" << endl;
            cout << endl;
            cout << "安装完成后，按任意键继续..." << endl;
            cout << "========================================" << endl;
            system("pause");
            cout << endl;
        }

        // 循环检测（无论自动安装是否成功都要检测）
        cout << "  检测虚拟网卡..." << endl;
        for (int retry = 0; retry < 15; retry++) {
            adapter_name = find_loopback_adapter_name();
            if (!adapter_name.empty()) {
                cout << "  ✓ 检测到虚拟网卡: " << adapter_name << endl;
                Logger::info("[1/3] 检测到虚拟网卡: " + adapter_name);
                break;
            }
            if (retry < 14) {
                cout << "  等待中... (" << (retry + 1) << "/15)" << endl;
                Sleep(2000);
            }
        }

        if (adapter_name.empty()) {
            cout << "  ✗ 未检测到虚拟网卡，程序无法继续" << endl;
            Logger::error("[1/3] 未检测到虚拟网卡");
            return false;
        }
    } else {
        cout << "  ✓ 找到虚拟网卡: " << adapter_name << endl;
        Logger::info("[1/3] 找到虚拟网卡: " + adapter_name);
    }

    cout << endl;

    // 2. 配置IP地址（使用动态IP）
    cout << "[2/3] 配置IP地址..." << endl;
    Logger::info("[2/3] 配置IP地址");
    if (!configure_loopback_ips(adapter_name, primary_ip, secondary_ip)) {
        return false;
    }

    cout << endl;

    // 3. 查询IfIdx
    cout << "[3/3] 查询网卡索引..." << endl;
    Logger::info("[3/3] 查询网卡索引");
    UINT32 ifidx = query_loopback_ifidx(adapter_name);
    if (ifidx == 0) {
        cout << "  ✗ 无法查询IfIdx" << endl;
        Logger::error("[3/3] 无法查询IfIdx");
        return false;
    }

    cout << "  ✓ 网卡索引: " << ifidx << endl;
    Logger::info("[3/3] IfIdx=" + to_string(ifidx));

    // 设置全局变量
    g_loopback_adapter_ifidx = ifidx;

    cout << endl;
    cout << "========================================" << endl;
    cout << "✓ 虚拟网卡配置完成" << endl;
    cout << "  网卡名称: " << adapter_name << endl;
    cout << "  主IP（游戏服务器）: " << primary_ip << endl;
    cout << "  辅助IP（虚拟客户端）: " << secondary_ip << endl;
    cout << "  IfIdx: " << ifidx << endl;
    cout << "========================================" << endl;
    cout << endl;

    Logger::info("========================================");
    Logger::info("✓ 虚拟网卡配置完成");
    Logger::info("  网卡: " + adapter_name + ", 主IP: " + primary_ip + ", 辅助IP: " + secondary_ip + ", IfIdx: " + to_string(ifidx));
    Logger::info("========================================");

    return true;
}

// ==================== 工具函数 ====================
uint16_t calculate_checksum(const uint8_t* data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len - 1; i += 2) {
        sum += (data[i] << 8) | data[i + 1];
    }
    if (len % 2 == 1) {
        sum += data[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

void ip_str_to_bytes(const string& ip, uint8_t* bytes) {
    int a, b, c, d;
    sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
    bytes[0] = a; bytes[1] = b; bytes[2] = c; bytes[3] = d;
}

// ==================== TCP连接类 ====================
class TCPConnection {
private:
    int conn_id;
    string src_ip;
    uint16_t src_port;
    string dst_ip;
    uint16_t dst_port;
    string tunnel_server_ip;
    uint16_t tunnel_port;
    HANDLE windivert_handle;
    WINDIVERT_ADDRESS interface_addr;

    // TCP序列号
    uint32_t client_seq;
    uint32_t client_ack;
    uint32_t server_seq;
    uint32_t server_ack;
    mutex seq_lock;

    // IP包ID
    uint16_t ip_id;

    // 窗口管理
    uint16_t client_window;
    uint16_t advertised_window;
    uint16_t data_window;

    // 发送缓冲区
    uint32_t client_acked_seq;
    vector<uint8_t> send_buffer;
    mutex send_lock;

    // 隧道连接
    SOCKET tunnel_sock;
    atomic<bool> running;
    bool established;
    atomic<bool> closing;

    // 窗口探测
    DWORD last_window_probe_time;
    DWORD window_zero_start_time;
    bool window_probe_logged;

public:
    TCPConnection(int id, const string& sip, uint16_t sport,
                  const string& dip, uint16_t dport,
                  const string& tunnel_ip, uint16_t tport,
                  HANDLE wdhandle, const WINDIVERT_ADDRESS& iface)
        : conn_id(id), src_ip(sip), src_port(sport),
          dst_ip(dip), dst_port(dport),
          tunnel_server_ip(tunnel_ip), tunnel_port(tport),
          windivert_handle(wdhandle), interface_addr(iface),
          client_seq(0), client_ack(0), server_seq(12345), server_ack(0),
          ip_id(10000), client_window(65535),
          advertised_window(29200),
          client_acked_seq(0),
          tunnel_sock(INVALID_SOCKET), running(false), established(false), closing(false),
          last_window_probe_time(0), window_zero_start_time(0), window_probe_logged(false) {

        // 根据端口设置窗口
        if (dport == 10011) {
            data_window = 245;
        } else if (dport == 7001) {
            data_window = 228;
        } else {
            data_window = 229;
        }
    }

    ~TCPConnection() {
        stop();
        if (tunnel_sock != INVALID_SOCKET) {
            closesocket(tunnel_sock);
        }
    }

    void handle_syn(uint32_t seq) {
        uint32_t old_server_seq = server_seq;
        Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                    "] 收到SYN seq=" + to_string(seq) + " (窗口=" + to_string(data_window) +
                    ", 旧server_seq=" + to_string(old_server_seq) + ")");

        // 重置TCP状态
        client_seq = seq;
        server_seq = 12345;  // 重置为初始值
        server_ack = seq + 1;
        client_ack = 0;
        client_acked_seq = 0;
        established = false;

        Logger::debug("[连接" + to_string(conn_id) + "] TCP状态已重置 server_seq=" + to_string(server_seq));

        // 清空缓冲区
        {
            lock_guard<mutex> lock(send_lock);
            send_buffer.clear();
        }

        // 连接到隧道服务器 - 使用getaddrinfo支持域名/IPv4/IPv6
        struct addrinfo hints{}, *result = nullptr, *rp = nullptr;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;      // 允许IPv4或IPv6
        hints.ai_socktype = SOCK_STREAM;  // TCP
        hints.ai_protocol = IPPROTO_TCP;

        string port_str = to_string(tunnel_port);
        int ret = getaddrinfo(tunnel_server_ip.c_str(), port_str.c_str(), &hints, &result);
        if (ret != 0) {
            Logger::error("[连接" + to_string(conn_id) + "] DNS解析失败: " + tunnel_server_ip +
                         " (错误: " + to_string(ret) + ")");
            running = false;
            return;
        }

        // 尝试连接所有解析结果
        bool connected = false;
        for (rp = result; rp != nullptr; rp = rp->ai_next) {
            tunnel_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (tunnel_sock == INVALID_SOCKET) {
                continue;
            }

            Logger::debug("[连接" + to_string(conn_id) + "] 尝试连接隧道 (协议: " +
                         string(rp->ai_family == AF_INET ? "IPv4" : "IPv6") + ")");

            // TCP_NODELAY
            int flag = 1;
            setsockopt(tunnel_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

            // 连接超时设置
            DWORD timeout = 5000;
            setsockopt(tunnel_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
            setsockopt(tunnel_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

            if (connect(tunnel_sock, rp->ai_addr, (int)rp->ai_addrlen) != SOCKET_ERROR) {
                connected = true;
                Logger::debug("[连接" + to_string(conn_id) + "] 隧道连接成功");
                break;
            }

            // 连接失败，尝试下一个地址
            Logger::debug("[连接" + to_string(conn_id) + "] 连接尝试失败，尝试下一个地址");
            closesocket(tunnel_sock);
            tunnel_sock = INVALID_SOCKET;
        }

        freeaddrinfo(result);

        if (!connected || tunnel_sock == INVALID_SOCKET) {
            Logger::error("[连接" + to_string(conn_id) + "] 连接隧道服务器失败: " +
                         tunnel_server_ip + ":" + to_string(tunnel_port) + " (所有地址均失败)");
            running = false;
            return;
        }

        // 发送握手：conn_id(4) + dst_port(2)
        uint8_t handshake[6];
        *(uint32_t*)handshake = htonl(conn_id);
        *(uint16_t*)(handshake + 4) = htons(dst_port);

        if (send(tunnel_sock, (char*)handshake, 6, 0) != 6) {
            Logger::error("[连接" + to_string(conn_id) + "] 发送握手失败");
            closesocket(tunnel_sock);
            tunnel_sock = INVALID_SOCKET;
            running = false;
            return;
        }

        Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                    "] 隧道已建立 -> " + tunnel_server_ip + ":" + to_string(tunnel_port) +
                    " (TCP_NODELAY, 窗口=" + to_string(data_window) + ")");

        // 发送SYN-ACK
        send_syn_ack();

        // SYN标志消耗1个序列号，所以立即增加server_seq
        server_seq += 1;
        client_acked_seq = server_seq;
        Logger::debug("[连接" + to_string(conn_id) + "] SYN-ACK已发送，server_seq更新为 " + to_string(server_seq));

        // 启动接收线程
        running = true;
        // 取消超时
        DWORD recv_timeout = 0;
        setsockopt(tunnel_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&recv_timeout, sizeof(recv_timeout));

        thread([this]() {
            recv_from_tunnel();
        }).detach();
    }

    void update_window(uint16_t window) {
        if (window != client_window) {
            uint16_t old_window = client_window;
            client_window = window;

            if (window < 8192 || window == 0) {
                Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                           "] 游戏客户端窗口变化: " + to_string(old_window) + " → " +
                           to_string(window) + "字节");
            }

            // 窗口打开时，尝试发送缓冲区数据
            if (old_window < window && window > 0) {
                lock_guard<mutex> lock(send_lock);
                if (!send_buffer.empty()) {
                    Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                                "] 窗口扩大，尝试发送缓冲区数据");
                    try_send_buffered_data();
                }
            }
        }
    }

    void handle_ack(uint32_t seq, uint32_t ack) {
        Logger::debug("[连接" + to_string(conn_id) + "] handle_ack: 收到ack=" + to_string(ack) +
                     ", server_seq=" + to_string(server_seq) + ", 匹配=" +
                     (ack == server_seq ? "是" : "否"));

        if (!established && ack == server_seq) {
            established = true;
            client_ack = ack;
            // server_seq已经在发送SYN-ACK后增加过了，不需要再+1
            Logger::info("[连接" + to_string(conn_id) + "] ✓ TCP连接已建立 (收到ACK=" + to_string(ack) + ")");

            // 连接建立后，尝试发送缓冲区中的数据
            {
                lock_guard<mutex> lock(send_lock);
                if (!send_buffer.empty()) {
                    Logger::debug("[连接" + to_string(conn_id) + "] 连接已建立，发送缓冲区中的 " +
                                to_string(send_buffer.size()) + "字节");
                    try_send_buffered_data();
                }
            }
        }
    }

    void handle_data(uint32_t seq, uint32_t ack, const uint8_t* payload, int len) {
        if (!established) {
            Logger::warning("[连接" + to_string(conn_id) + "] 连接未建立，忽略数据");
            return;
        }

        Logger::debug("[连接" + to_string(conn_id) + "] 收到数据包 seq=" + to_string(seq) +
                     " ack=" + to_string(ack) + " payload=" + to_string(len) + "字节");

        // 更新客户端ACK
        update_client_ack(ack);

        if (len > 0) {
            // 打印完整载荷（16字节一行，格式化显示）
            string hex_dump = "";
            for (int i = 0; i < len; i++) {
                if (i > 0 && i % 16 == 0) {
                    hex_dump += "\n                    ";
                }
                char buf[4];
                sprintf(buf, "%02x ", payload[i]);
                hex_dump += buf;
            }

            Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                        "] ←[游戏客户端] 收到数据 " + to_string(len) + "字节 seq=" + to_string(seq) +
                        "\n                    " + hex_dump);

            // 转发到隧道：msg_type(1) + conn_id(4) + data_len(2) + payload
            vector<uint8_t> packet(7 + len);
            packet[0] = 0x01;
            *(uint32_t*)&packet[1] = htonl(conn_id);
            *(uint16_t*)&packet[5] = htons(len);
            memcpy(&packet[7], payload, len);

            if (send(tunnel_sock, (char*)packet.data(), packet.size(), 0) != (int)packet.size()) {
                Logger::error("[连接" + to_string(conn_id) + "] 转发数据失败");
                running = false;
                return;
            }

            Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                        "] →[隧道] 已转发 " + to_string(len) + "字节");

            // 更新序列号并发送ACK
            {
                lock_guard<mutex> lock(seq_lock);
                server_ack = seq + len;
            }
            send_ack();
            Logger::debug("[连接" + to_string(conn_id) + "] 发送ACK ack=" + to_string(server_ack));
        }
    }

    void update_client_ack(uint32_t ack) {
        lock_guard<mutex> lock(send_lock);
        if (ack > client_acked_seq) {
            client_acked_seq = ack;
            Logger::debug("[连接" + to_string(conn_id) + "] 游戏确认seq: " + to_string(ack));

            // 尝试发送缓冲数据
            if (!send_buffer.empty()) {
                try_send_buffered_data();
            }
        }
    }

    void stop() {
        running = false;
    }

    bool is_running() const {
        return running;
    }

    bool is_established() const {
        return established;
    }

    void handle_fin(uint32_t seq) {
        if (closing) {
            return;  // 已经在关闭过程中
        }

        closing = true;
        Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                    "] 收到FIN seq=" + to_string(seq) + "，开始关闭连接");

        // FIN消耗1个序列号
        {
            lock_guard<mutex> lock(seq_lock);
            server_ack = seq + 1;
        }

        // 关闭隧道连接
        stop();
        if (tunnel_sock != INVALID_SOCKET) {
            shutdown(tunnel_sock, SD_BOTH);
            Logger::debug("[连接" + to_string(conn_id) + "] 隧道socket已shutdown");
        }

        // 发送FIN-ACK回复游戏客户端
        send_fin_ack();
    }

private:
    void send_syn_ack() {
        auto packet = build_complete_packet(0x12, server_seq, server_ack, nullptr, 0, advertised_window);
        Logger::debug("[连接" + to_string(conn_id) + "] 发送SYN-ACK seq=" +
                    to_string(server_seq) + " ack=" + to_string(server_ack));
        inject_packet(packet);
    }

    void send_ack() {
        uint32_t seq, ack;
        {
            lock_guard<mutex> lock(seq_lock);
            seq = server_seq;
            ack = server_ack;
        }

        auto packet = build_complete_packet(0x10, seq, ack, nullptr, 0, data_window);
        inject_packet(packet);
    }

    void send_window_probe() {
        // 发送1字节窗口探测包，强制接收方回复ACK更新窗口大小
        if (send_buffer.empty())
            return;

        uint8_t probe_byte = send_buffer[0];
        uint32_t current_seq, current_ack;
        {
            lock_guard<mutex> lock(seq_lock);
            current_seq = server_seq;
            current_ack = server_ack;
            // 不增加seq，因为这是探测包，不消耗序列号空间
        }

        auto packet = build_complete_packet(0x18, current_seq, current_ack,
                                            &probe_byte, 1, data_window);
        inject_packet(packet);
        Logger::warning("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                       "] ⚠ 发送窗口探测包 (1字节) seq=" + to_string(current_seq));
    }

    void send_fin_ack() {
        // 发送FIN-ACK给游戏客户端，完成四次挥手
        uint32_t current_seq, current_ack;
        {
            lock_guard<mutex> lock(seq_lock);
            current_seq = server_seq;
            current_ack = server_ack;
            // FIN标志消耗1个序列号
            server_seq += 1;
        }

        // 0x11 = FIN(0x01) + ACK(0x10)
        auto packet = build_complete_packet(0x11, current_seq, current_ack,
                                            nullptr, 0, data_window);
        inject_packet(packet);
        Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                    "] 发送FIN-ACK seq=" + to_string(current_seq) +
                    " ack=" + to_string(current_ack) + " (关闭连接)");
    }

    void recv_from_tunnel() {
        vector<uint8_t> buffer;
        uint8_t recv_buf[4096];
        const int MAX_SEND_BUFFER = 8192;

        Logger::debug("[连接" + to_string(conn_id) + "] 隧道接收线程已启动");

        while (running) {
            // 反压监控（仅记录警告，不暂停接收）
            {
                lock_guard<mutex> lock(send_lock);
                if (send_buffer.size() > 65536) {
                    // 只在超过64KB时记录警告
                    int in_flight = server_seq - client_acked_seq;
                    int window_available = max(0, (int)client_window - in_flight);

                    Logger::warning("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                                  "] ⚠ 缓冲区过大: " + to_string(send_buffer.size()) + "字节 " +
                                  "(窗口:" + to_string(client_window) +
                                  " 飞行:" + to_string(in_flight) +
                                  " 可用:" + to_string(window_available) + ")");
                }
            }

            int n = recv(tunnel_sock, (char*)recv_buf, sizeof(recv_buf), 0);
            if (n <= 0) {
                int err = WSAGetLastError();
                Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                            "] 隧道关闭 (返回值:" + to_string(n) + " 错误:" + to_string(err) + ")");
                break;
            }

            Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                        "] ←[隧道] 接收 " + to_string(n) + "字节");
            buffer.insert(buffer.end(), recv_buf, recv_buf + n);

            // 解析：msg_type(1) + conn_id(4) + data_len(2) + data
            while (buffer.size() >= 7) {
                uint8_t msg_type = buffer[0];
                uint32_t msg_conn_id = ntohl(*(uint32_t*)&buffer[1]);
                uint16_t data_len = ntohs(*(uint16_t*)&buffer[5]);

                if (msg_conn_id != (uint32_t)conn_id) {
                    Logger::warning("[连接" + to_string(conn_id) + "] 收到错误连接ID: " +
                                  to_string(msg_conn_id));
                    break;
                }

                if (msg_type != 0x01) {
                    Logger::warning("[连接" + to_string(conn_id) + "] 未知消息类型: " +
                                  to_string((int)msg_type));
                    buffer.erase(buffer.begin(), buffer.begin() + 7);
                    continue;
                }

                if (buffer.size() < 7 + data_len) {
                    Logger::debug("[连接" + to_string(conn_id) + "] 等待更多数据");
                    break;
                }

                vector<uint8_t> payload(buffer.begin() + 7, buffer.begin() + 7 + data_len);
                buffer.erase(buffer.begin(), buffer.begin() + 7 + data_len);

                // 打印完整载荷（16字节一行，格式化显示）
                string hex_dump = "";
                for (int i = 0; i < (int)payload.size(); i++) {
                    if (i > 0 && i % 16 == 0) {
                        hex_dump += "\n                    ";
                    }
                    char buf[4];
                    sprintf(buf, "%02x ", payload[i]);
                    hex_dump += buf;
                }

                Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                            "] 解析隧道数据 " + to_string(payload.size()) + "字节\n                    " + hex_dump);

                send_data_to_client(payload);
            }
        }

        Logger::debug("[连接" + to_string(conn_id) + "] 隧道接收线程退出");
        running = false;
    }

    void send_data_to_client(const vector<uint8_t>& payload) {
        lock_guard<mutex> lock(send_lock);
        send_buffer.insert(send_buffer.end(), payload.begin(), payload.end());
        Logger::debug("[连接" + to_string(conn_id) + "] 缓冲区: " + to_string(send_buffer.size()) + "字节");
        try_send_buffered_data();
    }

    void try_send_buffered_data() {
        const int MAX_SEGMENT_SIZE = 1460;

        if (send_buffer.empty())
            return;

        // 连接未建立时不发送，只缓存
        if (!established) {
            Logger::debug("[连接" + to_string(conn_id) + "] 连接未建立，缓存 " +
                        to_string(send_buffer.size()) + "字节等待三次握手完成");
            return;
        }

        // 计算飞行中的数据量
        int in_flight = server_seq - client_acked_seq;
        int window_available = max(0, (int)client_window - in_flight);

        if (window_available == 0) {
            DWORD now = GetTickCount();

            // 记录窗口为0的开始时间
            if (window_zero_start_time == 0) {
                window_zero_start_time = now;
                window_probe_logged = false;
                Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                           "] 窗口已满 (飞行中:" + to_string(in_flight) +
                           ", 客户端窗口:" + to_string(client_window) +
                           ", 缓冲:" + to_string(send_buffer.size()) + "字节) - 开始窗口探测");
            }

            // 每1秒发送一次窗口探测包
            if (now - last_window_probe_time >= 1000) {
                send_window_probe();
                last_window_probe_time = now;
            }

            // 如果窗口已经0超过30秒，记录警告
            if (!window_probe_logged && now - window_zero_start_time > 30000) {
                Logger::warning("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                              "] ⚠⚠⚠ 窗口已阻塞超过30秒！缓冲:" + to_string(send_buffer.size()) + "字节");
                window_probe_logged = true;
            }

            return;
        }

        // 窗口已恢复，重置探测状态
        if (window_zero_start_time != 0) {
            DWORD blocked_time = GetTickCount() - window_zero_start_time;
            Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                       "] ✓ 窗口已恢复 (阻塞时间:" + to_string(blocked_time) + "ms)");
            window_zero_start_time = 0;
        }

        int can_send = min({window_available, MAX_SEGMENT_SIZE, (int)send_buffer.size()});
        vector<uint8_t> segment(send_buffer.begin(), send_buffer.begin() + can_send);
        send_buffer.erase(send_buffer.begin(), send_buffer.begin() + can_send);

        uint32_t current_seq, current_ack;
        {
            lock_guard<mutex> lock(seq_lock);
            current_seq = server_seq;
            current_ack = server_ack;
            server_seq += segment.size();
        }

        auto packet = build_complete_packet(0x18, current_seq, current_ack,
                                            segment.data(), segment.size(), data_window);
        Logger::debug("[连接" + to_string(conn_id) + "|端口" + to_string(dst_port) +
                   "] 注入数据到游戏 " + to_string(segment.size()) + "字节 seq=" +
                   to_string(current_seq) + " ack=" + to_string(current_ack) +
                   " win=" + to_string(data_window) + " (下一个seq=" + to_string(current_seq + segment.size()) + ")");
        inject_packet(packet);
    }

    vector<uint8_t> build_complete_packet(uint8_t flags, uint32_t seq, uint32_t ack,
                                          const uint8_t* payload, int payload_len,
                                          uint16_t window) {
        // 构造TCP头部（无校验和）
        uint8_t tcp_header[20];
        *(uint16_t*)&tcp_header[0] = htons(dst_port);  // 源端口（游戏服务器）
        *(uint16_t*)&tcp_header[2] = htons(src_port);  // 目标端口（游戏客户端）
        *(uint32_t*)&tcp_header[4] = htonl(seq);
        *(uint32_t*)&tcp_header[8] = htonl(ack);
        tcp_header[12] = 5 << 4;  // 数据偏移
        tcp_header[13] = flags;
        *(uint16_t*)&tcp_header[14] = htons(window);
        *(uint16_t*)&tcp_header[16] = 0;  // 校验和（稍后计算）
        *(uint16_t*)&tcp_header[18] = 0;  // 紧急指针

        // 构造伪头部
        uint8_t src_ip_bytes[4], dst_ip_bytes[4];
        ip_str_to_bytes(dst_ip, src_ip_bytes);  // 源IP（游戏服务器）
        ip_str_to_bytes(src_ip, dst_ip_bytes);  // 目标IP（游戏客户端）

        vector<uint8_t> pseudo_header(12);
        memcpy(&pseudo_header[0], src_ip_bytes, 4);
        memcpy(&pseudo_header[4], dst_ip_bytes, 4);
        pseudo_header[8] = 0;
        pseudo_header[9] = 6;  // TCP协议
        *(uint16_t*)&pseudo_header[10] = htons(20 + payload_len);

        // 计算TCP校验和
        vector<uint8_t> checksum_data = pseudo_header;
        checksum_data.insert(checksum_data.end(), tcp_header, tcp_header + 20);
        if (payload_len > 0) {
            checksum_data.insert(checksum_data.end(), payload, payload + payload_len);
        }

        uint16_t tcp_checksum = calculate_checksum(checksum_data.data(), checksum_data.size());
        *(uint16_t*)&tcp_header[16] = tcp_checksum;

        // 构造IP头部（无校验和）
        uint8_t ip_header[20];
        ip_header[0] = 0x45;  // 版本4 + 头长度5
        ip_header[1] = 0;  // TOS
        *(uint16_t*)&ip_header[2] = htons(20 + 20 + payload_len);  // 总长度
        *(uint16_t*)&ip_header[4] = htons(ip_id++);
        *(uint16_t*)&ip_header[6] = 0;  // 标志 + 片偏移
        ip_header[8] = 64;  // TTL
        ip_header[9] = 6;  // 协议（TCP）
        *(uint16_t*)&ip_header[10] = 0;  // 校验和（稍后计算）
        memcpy(&ip_header[12], src_ip_bytes, 4);
        memcpy(&ip_header[16], dst_ip_bytes, 4);

        // 计算IP校验和
        uint16_t ip_checksum = calculate_checksum(ip_header, 20);
        *(uint16_t*)&ip_header[10] = ip_checksum;

        // 组合完整包
        vector<uint8_t> packet;
        packet.insert(packet.end(), ip_header, ip_header + 20);
        packet.insert(packet.end(), tcp_header, tcp_header + 20);
        if (payload_len > 0) {
            packet.insert(packet.end(), payload, payload + payload_len);
        }

        return packet;
    }

    void inject_packet(vector<uint8_t>& packet) {
        // 使用WinDivert helper重新计算校验和
        WinDivertHelperCalcChecksums(packet.data(), packet.size(), NULL, 0);

        WINDIVERT_ADDRESS addr = interface_addr;
        addr.Outbound = 0;  // WinDivert 2.x: 0=inbound, 1=outbound

        UINT send_len = 0;
        if (!WinDivertSend(windivert_handle, packet.data(), packet.size(), &send_len, &addr)) {
            DWORD err = GetLastError();
            Logger::error("[连接" + to_string(conn_id) + "] 注入包失败: 错误码=" + to_string(err) +
                         " 包大小=" + to_string(packet.size()));
        } else {
            Logger::debug("[连接" + to_string(conn_id) + "] ✓ 注入成功 " + to_string(send_len) + "字节");
        }
    }
};

// ==================== UDP工具函数 ====================
// 注入UDP响应包回游戏
bool inject_udp_response(HANDLE windivert_handle,
                         const string& local_ip, uint16_t local_port,
                         const string& remote_ip, uint16_t remote_port,
                         const uint8_t* payload, size_t len,
                         const WINDIVERT_ADDRESS& interface_addr) {
    if (len > 65535) {
        Logger::error("[UDP] 响应包过大: " + to_string(len));
        return false;
    }

    // 构造完整UDP包: IP头(20) + UDP头(8) + payload
    vector<uint8_t> packet(20 + 8 + len);
    uint8_t* ip_header = packet.data();
    uint8_t* udp_header = packet.data() + 20;

    // === 构造IP头 ===
    ip_header[0] = 0x45;  // 版本4 + 头长度5
    ip_header[1] = 0;     // TOS
    *(uint16_t*)&ip_header[2] = htons((uint16_t)(20 + 8 + len));  // 总长度
    *(uint16_t*)&ip_header[4] = htons(rand() % 65536);  // IP ID
    *(uint16_t*)&ip_header[6] = 0;  // 标志 + 片偏移
    ip_header[8] = 64;   // TTL
    ip_header[9] = 17;   // 协议（UDP）
    *(uint16_t*)&ip_header[10] = 0;  // 校验和（稍后计算）

    // 源IP（游戏服务器）和目标IP（游戏客户端）
    uint8_t src_ip_bytes[4], dst_ip_bytes[4];
    ip_str_to_bytes(remote_ip, src_ip_bytes);
    ip_str_to_bytes(local_ip, dst_ip_bytes);
    memcpy(&ip_header[12], src_ip_bytes, 4);
    memcpy(&ip_header[16], dst_ip_bytes, 4);

    // === 构造UDP头 ===
    *(uint16_t*)&udp_header[0] = htons(remote_port);  // 源端口（游戏服务器）
    *(uint16_t*)&udp_header[2] = htons(local_port);   // 目标端口（游戏客户端）
    *(uint16_t*)&udp_header[4] = htons((uint16_t)(8 + len));  // UDP长度
    *(uint16_t*)&udp_header[6] = 0;  // 校验和（稍后计算）

    // 复制payload
    if (len > 0) {
        memcpy(udp_header + 8, payload, len);
    }

    // 使用WinDivert helper计算校验和
    WinDivertHelperCalcChecksums(packet.data(), (UINT)packet.size(), NULL, 0);

    // === 打印详细的注入信息 ===
    // 读取计算后的校验和
    uint16_t ip_checksum = ntohs(*(uint16_t*)&ip_header[10]);
    uint16_t udp_checksum = ntohs(*(uint16_t*)&udp_header[6]);

    Logger::info("[UDP注入] ========== 开始注入UDP响应 ==========");
    Logger::info("[UDP注入] IP: " + remote_ip + ":" + to_string(remote_port) +
                " → " + local_ip + ":" + to_string(local_port));
    Logger::info("[UDP注入] 包大小: " + to_string(packet.size()) + "字节 (IP头:20 + UDP头:8 + 载荷:" + to_string(len) + ")");

    // 打印IP头关键字段
    char ip_checksum_hex[8];
    sprintf(ip_checksum_hex, "0x%04x", ip_checksum);
    Logger::info("[UDP注入] IP校验和: " + string(ip_checksum_hex));

    // 打印UDP头关键字段
    char udp_checksum_hex[8];
    sprintf(udp_checksum_hex, "0x%04x", udp_checksum);
    Logger::info("[UDP注入] UDP校验和: " + string(udp_checksum_hex));

    // 打印完整payload hex dump
    if (len > 0) {
        string hex_dump = "";
        for (size_t i = 0; i < len; i++) {
            if (i > 0 && i % 16 == 0) {
                hex_dump += "\n                    ";
            }
            char buf[4];
            sprintf(buf, "%02x ", payload[i]);
            hex_dump += buf;
        }
        Logger::info("[UDP注入] Payload(" + to_string(len) + "字节):\n                    " + hex_dump);
    }

    // 打印完整IP+UDP包头(前28字节)
    string packet_header_hex = "";
    int header_len = min(28, (int)packet.size());
    for (int i = 0; i < header_len; i++) {
        if (i > 0 && i % 16 == 0) {
            packet_header_hex += "\n                    ";
        }
        char buf[4];
        sprintf(buf, "%02x ", packet[i]);
        packet_header_hex += buf;
    }
    Logger::info("[UDP注入] 完整包头(前" + to_string(header_len) + "字节):\n                    " + packet_header_hex);

    // v10.0: 注入包 - 根据配置选择物理网卡或虚拟网卡
    WINDIVERT_ADDRESS addr = {};
    addr.Outbound = 0;  // Inbound（发给游戏客户端）

    if (g_loopback_adapter_ifidx > 0) {
        // 使用虚拟网卡注入（绕过Windows跨子网源IP限制）
        addr.Network.IfIdx = g_loopback_adapter_ifidx;
        addr.Network.SubIfIdx = 0;
        Logger::info("[UDP注入] v10.0 使用虚拟网卡注入 (IfIdx=" + to_string(g_loopback_adapter_ifidx) + ")");
        Logger::info("[UDP注入] WinDivert方向: Inbound (Outbound=0)");
    } else {
        // 使用物理网卡注入（原有逻辑）
        addr = interface_addr;
        addr.Outbound = 0;
        Logger::info("[UDP注入] 使用物理网卡注入 (IfIdx=" + to_string(addr.Network.IfIdx) +
                    " SubIfIdx=" + to_string(addr.Network.SubIfIdx) + ")");
        Logger::info("[UDP注入] WinDivert方向: Inbound (Outbound=0)");
    }

    UINT send_len = 0;
    BOOL inject_result = WinDivertSend(windivert_handle, packet.data(), (UINT)packet.size(), &send_len, &addr);
    DWORD err = GetLastError();

    Logger::info("[UDP注入] WinDivertSend返回: " + string(inject_result ? "成功" : "失败") +
                ", 发送字节=" + to_string(send_len) +
                ", 期望字节=" + to_string(packet.size()) +
                ", WSA错误码=" + to_string(err));
    Logger::info("[UDP注入] ========== 注入完成 ==========");

    if (!inject_result) {
        Logger::error("[UDP] ❌ 注入UDP包失败: 错误码=" + to_string(err));
        return false;
    }

    Logger::info("[UDP|" + to_string(remote_port) + "→" + to_string(local_port) +
                 "] ✓ 成功注入UDP响应 " + to_string(len) + "字节");

    return true;
}

// ==================== 主客户端类 ====================
class TCPProxyClient {
private:
    string game_server_ip;
    string tunnel_server_ip;
    uint16_t tunnel_port;
    string secondary_ip;  // v12.1.0: 虚拟客户端IP（动态）

    HANDLE windivert_handle;
    atomic<bool> running;

    int conn_id_counter;
    map<tuple<string, uint16_t, uint16_t>, TCPConnection*> connections;
    mutex conn_lock;

    // UDP管理 - 简化版 (直接转发,无per-connection对象)
    uint32_t udp_conn_id_counter;
    mutex udp_lock;
    SOCKET udp_tunnel_sock;  // UDP专用的tunnel连接
    atomic<bool> udp_tunnel_ready;  // UDP tunnel是否就绪

    // UDP端口映射表: key="local_ip:local_port:remote_ip:remote_port" -> conn_id
    map<string, uint32_t> udp_port_map;
    // UDP conn_id反查表: conn_id -> "local_ip:local_port:remote_ip:remote_port"
    map<uint32_t, string> udp_conn_map;
    // 保存客户端IP用于握手响应(从第一个UDP包获取)
    string udp_client_ip;
    // 保存UDP接口地址信息(从第一个UDP包获取)
    WINDIVERT_ADDRESS udp_interface_addr;
    bool udp_interface_addr_saved;

public:
    TCPProxyClient(const string& game_ip, const string& tunnel_ip, uint16_t tport, const string& sec_ip)
        : game_server_ip(game_ip), tunnel_server_ip(tunnel_ip), tunnel_port(tport), secondary_ip(sec_ip),
          windivert_handle(NULL), running(false),
          conn_id_counter(1),
          udp_conn_id_counter(100000),  // UDP连接ID从100000开始
          udp_tunnel_sock(INVALID_SOCKET),
          udp_tunnel_ready(false),
          udp_interface_addr_saved(false) {
        memset(&udp_interface_addr, 0, sizeof(udp_interface_addr));
    }

    ~TCPProxyClient() {
        stop();
    }

    bool start() {
        // 初始化Winsock
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            Logger::error("WSAStartup失败");
            return false;
        }

        Logger::debug("游戏服务器: " + game_server_ip);
        Logger::debug("隧道服务器: " + tunnel_server_ip + ":" + to_string(tunnel_port));

        // 检测游戏服务器IP类型（IPv4 or IPv6）并构造相应的WinDivert过滤器
        bool is_ipv6 = (game_server_ip.find(':') != string::npos);
        string filter;

        if (is_ipv6) {
            // IPv6过滤器
            filter = "ipv6.DstAddr == " + game_server_ip +
                    " and ((tcp and tcp.DstPort != 22) or (udp and udp.DstPort != 22))";
            Logger::debug("检测到IPv6地址，使用IPv6过滤器");
        } else {
            // IPv4过滤器
            filter = "ip.DstAddr == " + game_server_ip +
                    " and ((tcp and tcp.DstPort != 22) or (udp and udp.DstPort != 22))";
            Logger::debug("检测到IPv4地址，使用IPv4过滤器");
        }

        Logger::debug("WinDivert过滤器: " + filter);
        Logger::debug("注意: 已移除outbound限制，将拦截双向流量");

        // 打开WinDivert - 使用高优先级1000
        windivert_handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 1000, 0);
        if (windivert_handle == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            Logger::error("WinDivert打开失败: " + to_string(err));
            Logger::error("请确保以管理员权限运行，并且WinDivert驱动已正确安装");
            if (err == 87) {
                Logger::error("错误87: 过滤器语法错误");
            }
            return false;
        }

        Logger::debug("WinDivert已启动 (优先级:1000, 双向, 所有端口, 排除SSH:22)");

        running = true;

        // 启动处理线程
        thread([this]() {
            process_packets();
        }).detach();

        Logger::info("代理客户端已启动");

        return true;
    }

    void stop() {
        running = false;

        // 清理TCP连接
        {
            lock_guard<mutex> lock(conn_lock);
            for (auto& pair : connections) {
                pair.second->stop();
                delete pair.second;
            }
            connections.clear();
        }

        // 清理UDP tunnel
        {
            lock_guard<mutex> lock(udp_lock);
            udp_port_map.clear();
            udp_conn_map.clear();
            udp_client_ip.clear();
            if (udp_tunnel_sock != INVALID_SOCKET) {
                closesocket(udp_tunnel_sock);
                udp_tunnel_sock = INVALID_SOCKET;
            }
        }

        if (windivert_handle != NULL) {
            WinDivertClose(windivert_handle);
            windivert_handle = NULL;
        }

        WSACleanup();
        Logger::info("客户端已停止");
    }

    void wait() {
        while (running) {
            Sleep(1000);
        }
    }

private:
    void process_packets() {
        Logger::debug("开始处理数据包...");

        uint8_t packet_buf[65536];
        WINDIVERT_ADDRESS addr;
        UINT packet_len;

        // 添加统计和心跳
        DWORD last_heartbeat = GetTickCount();
        DWORD last_packet_time = GetTickCount();
        int total_intercepted = 0;
        int tcp_count = 0;
        int udp_count = 0;

        while (running) {
            // 心跳监控 - 每5秒输出一次状态
            DWORD now = GetTickCount();
            if (now - last_heartbeat > 5000) {
                DWORD idle_time = now - last_packet_time;
                Logger::debug("[心跳] WinDivert运行中 - TCP:" + to_string(tcp_count) +
                           " UDP:" + to_string(udp_count) + " 总计:" + to_string(total_intercepted) +
                           " 空闲:" + to_string(idle_time) + "ms");
                last_heartbeat = now;

                // 如果超过10秒没有包，发出警告
                if (idle_time > 10000) {
                    Logger::warning("[!] 超过10秒未拦截到包，WinDivert可能失效或游戏已关闭");
                }
            }

            if (!WinDivertRecv(windivert_handle, packet_buf, sizeof(packet_buf), &packet_len, &addr)) {
                DWORD err = GetLastError();
                if (err == ERROR_NO_DATA) {
                    continue;
                }
                Logger::error("接收包失败: " + to_string(err) +
                            " (最后成功:" + to_string(now - last_packet_time) + "ms前)");
                break;
            }

            // 成功接收到包
            total_intercepted++;
            last_packet_time = GetTickCount();

            // 解析IP头
            if (packet_len < 20) continue;

            int ip_header_len = (packet_buf[0] & 0x0F) * 4;
            if (packet_len < ip_header_len) continue;

            uint8_t protocol = packet_buf[9];

            // 解析IP地址
            string src_ip = to_string(packet_buf[12]) + "." + to_string(packet_buf[13]) + "." +
                          to_string(packet_buf[14]) + "." + to_string(packet_buf[15]);
            string dst_ip = to_string(packet_buf[16]) + "." + to_string(packet_buf[17]) + "." +
                          to_string(packet_buf[18]) + "." + to_string(packet_buf[19]);

            if (protocol == 6) {  // TCP
                tcp_count++;  // 统计TCP包
                int tcp_offset = ip_header_len;
                if (packet_len < tcp_offset + 20) continue;

                uint16_t src_port = ntohs(*(uint16_t*)&packet_buf[tcp_offset]);
                uint16_t dst_port = ntohs(*(uint16_t*)&packet_buf[tcp_offset + 2]);
                uint32_t seq = ntohl(*(uint32_t*)&packet_buf[tcp_offset + 4]);
                uint32_t ack = ntohl(*(uint32_t*)&packet_buf[tcp_offset + 8]);
                int tcp_header_len = ((packet_buf[tcp_offset + 12] >> 4) & 0x0F) * 4;
                uint8_t flags = packet_buf[tcp_offset + 13];
                uint16_t window = ntohs(*(uint16_t*)&packet_buf[tcp_offset + 14]);

                int payload_offset = ip_header_len + tcp_header_len;
                int payload_len = packet_len - payload_offset;
                const uint8_t* payload = (payload_len > 0) ? &packet_buf[payload_offset] : nullptr;

                handle_tcp_packet(src_ip, src_port, dst_ip, dst_port, seq, ack, flags, window,
                                payload, payload_len, addr);
            }
            else if (protocol == 17) {  // UDP
                udp_count++;  // 统计UDP包
                int udp_offset = ip_header_len;
                if (packet_len < udp_offset + 8) continue;

                uint16_t src_port = ntohs(*(uint16_t*)&packet_buf[udp_offset]);
                uint16_t dst_port = ntohs(*(uint16_t*)&packet_buf[udp_offset + 2]);
                uint16_t udp_len = ntohs(*(uint16_t*)&packet_buf[udp_offset + 4]);

                int payload_offset = udp_offset + 8;
                int payload_len = packet_len - payload_offset;
                const uint8_t* payload = (payload_len > 0) ? &packet_buf[payload_offset] : nullptr;

                handle_udp_packet(src_ip, src_port, dst_ip, dst_port,
                                 payload, payload_len, addr);
            }

            // 包被拦截，不重新注入（DROP）
        }
    }

    void handle_tcp_packet(const string& src_ip, uint16_t src_port,
                          const string& dst_ip, uint16_t dst_port,
                          uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window,
                          const uint8_t* payload, int payload_len,
                          const WINDIVERT_ADDRESS& addr) {
        // 显示所有拦截的包
        string flags_str = "";
        if (flags & 0x01) flags_str += "FIN ";
        if (flags & 0x02) flags_str += "SYN ";
        if (flags & 0x04) flags_str += "RST ";
        if (flags & 0x08) flags_str += "PSH ";
        if (flags & 0x10) flags_str += "ACK ";
        if (flags_str.empty()) flags_str = "NONE";

        // 打印载荷前8字节（用于诊断）
        string payload_preview = "";
        if (payload_len > 0) {
            int preview_len = min(8, payload_len);
            for (int i = 0; i < preview_len; i++) {
                char buf[4];
                sprintf(buf, "%02x ", payload[i]);
                payload_preview += buf;
            }
            if (payload_len > 8) payload_preview += "...";
        }

        Logger::debug("[🔍拦截] " + to_string(src_port) + "→" + to_string(dst_port) +
                   " [" + flags_str + "] seq=" + to_string(seq) +
                   " ack=" + to_string(ack) + " win=" + to_string(window) +
                   " 载荷=" + to_string(payload_len) + "字节" +
                   (payload_len > 0 ? " [" + payload_preview + "]" : ""));

        // 检测退出请求特征（10011端口）
        if (dst_port == 10011 && payload_len >= 4 && payload != nullptr) {
            // 退出请求特征: 01 03 00 1d (29字节) 或包含该特征的包
            if (payload[0] == 0x01 && payload[1] == 0x03 && payload[2] == 0x00 && payload[3] == 0x1d) {
                Logger::warning("[⚠退出] 检测到游戏退出请求! 端口:" + to_string(dst_port) +
                              " 载荷:" + to_string(payload_len) + "字节");

                // 打印完整载荷
                string full_hex = "";
                for (int i = 0; i < min(64, payload_len); i++) {
                    char buf[4];
                    sprintf(buf, "%02x ", payload[i]);
                    full_hex += buf;
                    if ((i + 1) % 16 == 0) full_hex += "\n                    ";
                }
                if (payload_len > 64) full_hex += "...";
                Logger::warning("  完整载荷:\n                    " + full_hex);
            }
            // 也检测嵌入在大包中的退出请求（如135字节包）
            else if (payload_len >= 29) {
                for (int i = 0; i <= payload_len - 29; i++) {
                    if (payload[i] == 0x01 && payload[i+1] == 0x03 &&
                        payload[i+2] == 0x00 && payload[i+3] == 0x1d) {
                        Logger::warning("[⚠退出] 检测到嵌入的游戏退出请求! 端口:" + to_string(dst_port) +
                                      " 载荷:" + to_string(payload_len) + "字节 偏移:" + to_string(i));

                        string full_hex = "";
                        for (int j = 0; j < min(64, payload_len); j++) {
                            char buf[4];
                            sprintf(buf, "%02x ", payload[j]);
                            full_hex += buf;
                            if ((j + 1) % 16 == 0) full_hex += "\n                    ";
                        }
                        if (payload_len > 64) full_hex += "...";
                        Logger::warning("  完整载荷:\n                    " + full_hex);
                        break;  // 只报告第一次匹配
                    }
                }
            }
        }

        auto conn_key = make_tuple(src_ip, src_port, dst_port);

        lock_guard<mutex> lock(conn_lock);
        TCPConnection* conn = nullptr;

        auto it = connections.find(conn_key);
        if (it != connections.end()) {
            conn = it->second;
        }

        if (flags & 0x02) {  // SYN
            if (conn) {
                // 已存在旧连接，先清理
                Logger::debug("[连接] 收到新SYN，清理旧连接 (端口" + to_string(dst_port) + ")");
                conn->stop();
                delete conn;
                conn = nullptr;
            }

            // 创建新连接
            int conn_id = conn_id_counter++;
            conn = new TCPConnection(conn_id, src_ip, src_port, dst_ip, dst_port,
                                    tunnel_server_ip, tunnel_port,
                                    windivert_handle, addr);
            connections[conn_key] = conn;

            conn->handle_syn(seq);
            conn->update_window(window);
        }
        else if (conn) {
            conn->update_window(window);

            if (flags & 0x01) {  // FIN
                conn->handle_fin(seq);
                // 短暂延迟后删除连接，确保FIN-ACK发送完成
                Sleep(100);
                delete conn;
                connections.erase(conn_key);
                Logger::debug("[连接] FIN处理完成，连接已清理");
            }
            else if (flags & 0x04) {  // RST
                Logger::debug("[连接] 收到RST，关闭连接");
                conn->stop();
                delete conn;
                connections.erase(conn_key);
            }
            else if (flags & 0x10) {  // ACK
                if (!conn->is_established()) {
                    // 三次握手的第三步
                    Logger::debug("[连接] 收到第三次握手ACK seq=" + to_string(seq) +
                               " ack=" + to_string(ack) + " (期望ack=server_seq)");
                    conn->handle_ack(seq, ack);
                }
                else if (payload_len > 0) {
                    conn->handle_data(seq, ack, payload, payload_len);
                }
                else {
                    // 纯ACK
                    Logger::debug("[连接] 收到纯ACK seq=" + to_string(seq) +
                               " ack=" + to_string(ack) + " win=" + to_string(window) +
                               " (游戏确认收到数据)");
                    conn->update_client_ack(ack);
                }
            }
        }
        else {
            // 连接不存在，但收到了非SYN包
            if (!(flags & 0x02)) {  // 不是SYN
                Logger::warning("[🔍拦截] 端口" + to_string(src_port) + "→" + to_string(dst_port) +
                              " 连接不存在但收到 [" + flags_str + "] 包" +
                              (payload_len > 0 ? " 载荷=" + to_string(payload_len) + "字节" : ""));
            }
        }
    }

    void handle_udp_packet(const string& src_ip, uint16_t src_port,
                          const string& dst_ip, uint16_t dst_port,
                          const uint8_t* payload, int payload_len,
                          const WINDIVERT_ADDRESS& addr) {
        // 打印完整载荷（16字节一行，格式化显示）
        string hex_dump = "";
        if (payload_len > 0) {
            for (int i = 0; i < payload_len; i++) {
                if (i > 0 && i % 16 == 0) {
                    hex_dump += "\n                    ";
                }
                char buf[4];
                sprintf(buf, "%02x ", payload[i]);
                hex_dump += buf;
            }
        }

        Logger::info("[🔍拦截UDP] " + to_string(src_port) + "→" + to_string(dst_port) +
                   " 载荷=" + to_string(payload_len) + "字节" +
                   (payload_len > 0 ? "\n                    " + hex_dump : ""));

        // 首次建立UDP tunnel连接(如果还没有)
        if (udp_tunnel_sock == INVALID_SOCKET) {
            lock_guard<mutex> lock(udp_lock);
            if (udp_tunnel_sock == INVALID_SOCKET) {  // Double-check
                if (!create_udp_tunnel()) {
                    Logger::error("[UDP] 创建UDP tunnel连接失败");
                    return;
                }
            }
        }

        // 查找或分配conn_id
        string port_key = src_ip + ":" + to_string(src_port) + ":" + dst_ip + ":" + to_string(dst_port);
        uint32_t conn_id;

        {
            lock_guard<mutex> lock(udp_lock);

            // 保存客户端IP(从第一个UDP包获取,用于握手响应)
            if (udp_client_ip.empty()) {
                udp_client_ip = src_ip;
                Logger::debug("[UDP] 保存客户端IP: " + udp_client_ip);
            }

            // 保存UDP接口地址信息(从第一个UDP包获取,用于注入响应)
            if (!udp_interface_addr_saved) {
                udp_interface_addr = addr;
                udp_interface_addr_saved = true;
                Logger::debug("[UDP] 保存接口地址: IfIdx=" + to_string(addr.Network.IfIdx) +
                            " SubIfIdx=" + to_string(addr.Network.SubIfIdx) +
                            " Direction=" + string(addr.Outbound ? "Outbound" : "Inbound"));
            }

            auto it = udp_port_map.find(port_key);
            if (it != udp_port_map.end()) {
                conn_id = it->second;
            } else {
                // 分配新的conn_id
                conn_id = udp_conn_id_counter++;
                udp_port_map[port_key] = conn_id;
                udp_conn_map[conn_id] = port_key;
                Logger::info("[UDP|" + to_string(conn_id) + "] 新UDP流: " +
                           src_ip + ":" + to_string(src_port) + " → " +
                           dst_ip + ":" + to_string(dst_port));
            }
        }

        // 直接构造tunnel协议并发送
        if (payload_len > 0 && payload != nullptr) {
            if (payload_len > 65535) {
                Logger::error("[UDP|" + to_string(conn_id) + "] 数据包过大: " + to_string(payload_len));
                return;
            }

            // 构造tunnel协议: msg_type(0x03) + conn_id(4) + src_port(2) + dst_port(2) + data_len(2) + payload
            vector<uint8_t> packet(11 + payload_len);
            packet[0] = 0x03;  // UDP消息类型
            *(uint32_t*)&packet[1] = htonl(conn_id);
            *(uint16_t*)&packet[5] = htons(src_port);
            *(uint16_t*)&packet[7] = htons(dst_port);
            *(uint16_t*)&packet[9] = htons((uint16_t)payload_len);
            memcpy(&packet[11], payload, payload_len);

            int sent = send(udp_tunnel_sock, (char*)packet.data(), (int)packet.size(), 0);
            if (sent != (int)packet.size()) {
                int err = WSAGetLastError();
                Logger::error("[UDP|" + to_string(conn_id) + "] 发送到tunnel失败: sent=" +
                            to_string(sent) + " expected=" + to_string(packet.size()) +
                            " WSA错误=" + to_string(err));
                return;
            }

            Logger::debug("[UDP|" + to_string(conn_id) + "|" + to_string(src_port) + "→" + to_string(dst_port) +
                         "] →[隧道] 已转发 " + to_string(payload_len) + "字节");
        }
    }

    // 创建UDP专用的tunnel连接
    bool create_udp_tunnel() {
        // 解析tunnel服务器地址
        struct addrinfo hints{}, *result = nullptr, *rp = nullptr;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        string port_str = to_string(tunnel_port);
        int ret = getaddrinfo(tunnel_server_ip.c_str(), port_str.c_str(), &hints, &result);
        if (ret != 0) {
            Logger::error("[UDP] DNS解析失败: " + tunnel_server_ip);
            return false;
        }

        // 尝试连接
        bool connected = false;
        for (rp = result; rp != nullptr; rp = rp->ai_next) {
            udp_tunnel_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (udp_tunnel_sock == INVALID_SOCKET) {
                continue;
            }

            // TCP_NODELAY
            int flag = 1;
            setsockopt(udp_tunnel_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

            if (connect(udp_tunnel_sock, rp->ai_addr, (int)rp->ai_addrlen) != SOCKET_ERROR) {
                connected = true;
                Logger::info("[UDP] Tunnel连接成功: " + tunnel_server_ip + ":" + to_string(tunnel_port));
                break;
            }

            closesocket(udp_tunnel_sock);
            udp_tunnel_sock = INVALID_SOCKET;
        }

        freeaddrinfo(result);

        if (!connected) {
            Logger::error("[UDP] 连接tunnel服务器失败");
            return false;
        }

        // 发送UDP tunnel握手: conn_id(4) = 0xFFFFFFFF (特殊标记) + port(2) = 10011 (使用真实端口)
        // 注意: 服务器会为每个tunnel创建一个TunnelConnection，UDP流量通过这个连接转发
        uint8_t handshake[6];
        *(uint32_t*)handshake = htonl(0xFFFFFFFF);  // 特殊conn_id标记UDP tunnel
        *(uint16_t*)(handshake + 4) = htons(10011);  // 使用10011端口作为默认游戏端口

        if (send(udp_tunnel_sock, (char*)handshake, 6, 0) != 6) {
            int err = WSAGetLastError();
            Logger::error("[UDP] 发送UDP握手失败: WSA错误=" + to_string(err));
            closesocket(udp_tunnel_sock);
            udp_tunnel_sock = INVALID_SOCKET;
            return false;
        }

        Logger::info("[UDP] 已发送握手请求(第一部分) (conn_id=0xFFFFFFFF, port=10011)");

        // ===== 新协议: 发送客户端IPv4地址(4字节) =====
        // v12.1.0: 使用虚拟网卡时，发送动态虚拟客户端IP而不是真实IP
        string interface_ipv4;
        if (g_loopback_adapter_ifidx > 0) {
            // 使用动态虚拟客户端IP（从配置自动计算的辅助IP）
            interface_ipv4 = secondary_ip;
            Logger::info("[UDP] v12.1.0 使用虚拟客户端IP: " + interface_ipv4 + " (payload中的客户端IP)");
        } else {
            // 获取该连接所在接口的IPv4地址
            interface_ipv4 = get_ipv4_from_socket_interface(udp_tunnel_sock);
            if (interface_ipv4.empty()) {
                Logger::error("[UDP] 无法获取连接接口的IPv4地址");
                closesocket(udp_tunnel_sock);
                udp_tunnel_sock = INVALID_SOCKET;
                return false;
            }
            Logger::info("[UDP] 连接接口的IPv4地址: " + interface_ipv4 + " (将发送给服务器用于源IP伪造)");
        }

        // 将IPv4字符串转换为4字节网络字节序
        sockaddr_in temp_addr{};
        if (inet_pton(AF_INET, interface_ipv4.c_str(), &temp_addr.sin_addr) != 1) {
            Logger::error("[UDP] IPv4地址格式转换失败: " + interface_ipv4);
            closesocket(udp_tunnel_sock);
            udp_tunnel_sock = INVALID_SOCKET;
            return false;
        }

        uint8_t ipv4_bytes[4];
        memcpy(ipv4_bytes, &temp_addr.sin_addr.s_addr, 4);

        // 发送IPv4地址(4字节，网络字节序)
        if (send(udp_tunnel_sock, (char*)ipv4_bytes, 4, 0) != 4) {
            int err = WSAGetLastError();
            Logger::error("[UDP] 发送IPv4地址失败: WSA错误=" + to_string(err));
            closesocket(udp_tunnel_sock);
            udp_tunnel_sock = INVALID_SOCKET;
            return false;
        }

        Logger::info("[UDP] 已发送客户端IPv4地址,等待服务器确认");

        // 等待服务器的握手确认(6字节: conn_id + port)
        uint8_t ack[6];
        DWORD timeout = 5000;  // 5秒超时
        setsockopt(udp_tunnel_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        int received = recv(udp_tunnel_sock, (char*)ack, 6, MSG_WAITALL);
        if (received != 6) {
            int err = WSAGetLastError();
            Logger::error("[UDP] 握手确认失败: received=" + to_string(received) +
                        " WSA错误=" + to_string(err));
            closesocket(udp_tunnel_sock);
            udp_tunnel_sock = INVALID_SOCKET;
            return false;
        }

        // 解析握手确认
        uint32_t ack_conn_id = ntohl(*(uint32_t*)ack);
        uint16_t ack_port = ntohs(*(uint16_t*)(ack + 4));

        if (ack_conn_id != 0xFFFFFFFF) {
            Logger::error("[UDP] 握手确认失败: 期望conn_id=0xFFFFFFFF, 收到=" + to_string(ack_conn_id));
            closesocket(udp_tunnel_sock);
            udp_tunnel_sock = INVALID_SOCKET;
            return false;
        }

        Logger::info("[UDP] ✓ 握手成功! 服务器已确认 (port=" + to_string(ack_port) + ")");

        // 取消接收超时,恢复为阻塞模式
        timeout = 0;
        setsockopt(udp_tunnel_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        // 标记UDP tunnel就绪
        udp_tunnel_ready = true;

        // 启动UDP响应接收线程
        thread([this]() {
            recv_udp_responses();
        }).detach();

        return true;
    }

    // 接收UDP响应的线程
    void recv_udp_responses() {
        Logger::info("[UDP] ========================================");
        Logger::info("[UDP] 响应接收线程已启动");
        Logger::info("[UDP] socket状态: " + string(udp_tunnel_sock != INVALID_SOCKET ? "有效" : "无效") +
                    " (sock=" + to_string(udp_tunnel_sock) + ")");
        Logger::info("[UDP] running状态: " + string(running ? "true" : "false"));
        Logger::info("[UDP] ========================================");

        vector<uint8_t> buffer;
        uint8_t recv_buf[4096];

        while (running && udp_tunnel_sock != INVALID_SOCKET) {
            Logger::info("[UDP] 准备调用recv() - socket=" + to_string(udp_tunnel_sock) +
                        ", buffer_size=" + to_string(sizeof(recv_buf)));

            int n = recv(udp_tunnel_sock, (char*)recv_buf, sizeof(recv_buf), 0);
            int err = WSAGetLastError();

            Logger::info("[UDP] recv()返回: n=" + to_string(n) +
                        ", WSAError=" + to_string(err));

            if (n <= 0) {
                if (n == 0) {
                    Logger::info("[UDP] Tunnel连接被服务器关闭 (recv返回0)");
                } else {
                    Logger::error("[UDP] recv()失败: 返回值=" + to_string(n) +
                                ", WSA错误=" + to_string(err));
                }
                Logger::info("[UDP] 退出接收循环");
                break;
            }

            Logger::info("[UDP] ✓ ←[Tunnel] 成功接收 " + to_string(n) + "字节");
            buffer.insert(buffer.end(), recv_buf, recv_buf + n);

            // 解析: msg_type(0x03) + conn_id(4) + src_port(2) + dst_port(2) + data_len(2) + payload
            while (buffer.size() >= 11) {
                uint8_t msg_type = buffer[0];
                if (msg_type != 0x03) {
                    Logger::warning("[UDP] 未知消息类型: " + to_string((int)msg_type));
                    buffer.erase(buffer.begin());
                    continue;
                }

                uint32_t conn_id = ntohl(*(uint32_t*)&buffer[1]);
                uint16_t src_port = ntohs(*(uint16_t*)&buffer[5]);
                uint16_t dst_port = ntohs(*(uint16_t*)&buffer[7]);
                uint16_t data_len = ntohs(*(uint16_t*)&buffer[9]);

                if (buffer.size() < 11 + data_len) {
                    Logger::debug("[UDP] 等待更多数据 (需要" + to_string(11 + data_len) +
                                "字节，当前" + to_string(buffer.size()) + "字节)");
                    break;
                }

                vector<uint8_t> payload(buffer.begin() + 11, buffer.begin() + 11 + data_len);
                buffer.erase(buffer.begin(), buffer.begin() + 11 + data_len);

                Logger::debug("[UDP] 解析响应: conn_id=" + to_string(conn_id) +
                            " " + to_string(src_port) + "→" + to_string(dst_port) +
                            " 数据=" + to_string(data_len) + "字节");

                // 特殊处理握手响应(conn_id=0xFFFFFFFF)
                if (conn_id == 0xFFFFFFFF) {
                    // 握手响应包,直接使用协议头的端口信息注入
                    // 协议格式: src_port=游戏服务器端口, dst_port=游戏客户端端口
                    // 响应方向: 游戏服务器 -> 游戏客户端,所以local=游戏客户端,remote=游戏服务器

                    string client_ip;
                    WINDIVERT_ADDRESS iface_addr;
                    bool addr_available;
                    {
                        lock_guard<mutex> lock(udp_lock);
                        client_ip = udp_client_ip;
                        iface_addr = udp_interface_addr;
                        addr_available = udp_interface_addr_saved;
                    }

                    if (!client_ip.empty() && addr_available) {
                        Logger::info("[UDP|握手响应] 准备注入握手响应: " +
                                   client_ip + ":" + to_string(dst_port) + " ← " +
                                   game_server_ip + ":" + to_string(src_port) +
                                   " (" + to_string(data_len) + "字节)");

                        inject_udp_response(windivert_handle,
                                          client_ip, dst_port,           // 本地游戏客户端
                                          game_server_ip, src_port,      // 远程游戏服务器
                                          payload.data(), payload.size(),
                                          iface_addr);

                        Logger::info("[UDP|握手响应] ✓ 已注入握手响应");
                    } else {
                        if (client_ip.empty()) {
                            Logger::warning("[UDP|握手响应] 无法注入握手响应: 客户端IP未知");
                        } else {
                            Logger::warning("[UDP|握手响应] 无法注入握手响应: 接口地址信息未就绪");
                        }
                    }
                    continue;  // 握手包处理完成
                }

                // 查找对应的UDP连接并注入响应
                string port_key;
                WINDIVERT_ADDRESS iface_addr;
                bool addr_available;
                {
                    lock_guard<mutex> lock(udp_lock);
                    auto it = udp_conn_map.find(conn_id);
                    if (it != udp_conn_map.end()) {
                        port_key = it->second;
                    }
                    iface_addr = udp_interface_addr;
                    addr_available = udp_interface_addr_saved;
                }

                if (!port_key.empty() && addr_available) {
                    // 解析port_key: "local_ip:local_port:remote_ip:remote_port"
                    size_t pos1 = port_key.find(':');
                    size_t pos2 = port_key.find(':', pos1 + 1);
                    size_t pos3 = port_key.find(':', pos2 + 1);

                    if (pos1 != string::npos && pos2 != string::npos && pos3 != string::npos) {
                        string local_ip = port_key.substr(0, pos1);
                        uint16_t local_port = (uint16_t)stoi(port_key.substr(pos1 + 1, pos2 - pos1 - 1));
                        string remote_ip = port_key.substr(pos2 + 1, pos3 - pos2 - 1);
                        uint16_t remote_port = (uint16_t)stoi(port_key.substr(pos3 + 1));

                        // 使用工具函数注入UDP响应
                        Logger::info("[UDP|" + to_string(conn_id) + "] 准备注入UDP响应: " +
                                   local_ip + ":" + to_string(local_port) + " ← " +
                                   remote_ip + ":" + to_string(src_port) +
                                   " (" + to_string(payload.size()) + "字节)");

                        inject_udp_response(windivert_handle, local_ip, local_port,
                                          remote_ip, src_port, payload.data(), payload.size(),
                                          iface_addr);
                    } else {
                        Logger::error("[UDP] 解析port_key失败: " + port_key);
                    }
                } else {
                    if (port_key.empty()) {
                        Logger::warning("[UDP] 未找到conn_id=" + to_string(conn_id) + "对应的映射");
                    } else {
                        Logger::warning("[UDP] 无法注入UDP响应: 接口地址信息未就绪");
                    }
                }
            }
        }

        Logger::info("[UDP] ========================================");
        Logger::info("[UDP] 响应接收线程退出");
        Logger::info("[UDP] 最终状态: running=" + string(running ? "true" : "false") +
                    ", socket=" + (udp_tunnel_sock != INVALID_SOCKET ? "有效" : "无效"));
        Logger::info("[UDP] ========================================");
    }
};

// ==================== 主函数 ====================
int main() {
    SetConsoleOutputCP(CP_UTF8);

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
        system("pause");
        return 1;
    }

    cout << "============================================================" << endl;
    cout << "DNF游戏代理客户端 v12.1.0 (C++ 版本 - 动态IP配置)" << endl;
    cout << "编译时间: " << __DATE__ << " " << __TIME__ << endl;
    cout << "============================================================" << endl;
    cout << endl;

    // ========== 步骤1: 读取配置（获取游戏服务器IP） ==========
    cout << "[步骤1/5] 读取配置..." << endl;
    string GAME_SERVER_IP;
    string TUNNEL_SERVER_IP;
    int TUNNEL_PORT;

    if (!read_config_from_self(GAME_SERVER_IP, TUNNEL_SERVER_IP, TUNNEL_PORT)) {
        cout << "错误: 无法读取配置" << endl;
        cout << endl;
        cout << "此程序需要配置才能运行。" << endl;
        cout << "请使用配置注入工具生成带配置的客户端程序。" << endl;
        cout << endl;
        Logger::close();
        system("pause");
        return 1;
    }

    cout << "✓ 配置读取成功" << endl;
    cout << "  游戏服务器: " << GAME_SERVER_IP << endl;
    cout << "  隧道服务器: " << TUNNEL_SERVER_IP << ":" << TUNNEL_PORT << endl;
    cout << endl;

    // ========== 步骤2: 计算辅助IP ==========
    cout << "[步骤2/5] 计算虚拟网卡IP分配方案..." << endl;
    string SECONDARY_IP = calculate_secondary_ip(GAME_SERVER_IP);
    if (SECONDARY_IP.empty()) {
        cout << "错误: 无法计算辅助IP地址" << endl;
        Logger::error("辅助IP计算失败");
        Logger::close();
        system("pause");
        return 1;
    }

    cout << "✓ IP分配方案：" << endl;
    cout << "  主IP（游戏服务器）: " << GAME_SERVER_IP << endl;
    cout << "  辅助IP（虚拟客户端）: " << SECONDARY_IP << endl;
    cout << endl;

    // ========== 步骤3: 配置虚拟网卡（使用动态IP） ==========
    cout << "[步骤3/5] 配置虚拟网卡..." << endl;
    if (!auto_setup_loopback_adapter(GAME_SERVER_IP, SECONDARY_IP)) {
        cout << "错误: 虚拟网卡配置失败，程序无法继续运行" << endl;
        Logger::error("虚拟网卡配置失败");
        Logger::close();
        system("pause");
        return 1;
    }

    // ========== 步骤4: 部署WinDivert ==========
    cout << "[步骤4/5] 部署WinDivert组件..." << endl;
    string dll_path, sys_path;
    if (!deploy_windivert_files(dll_path, sys_path)) {
        cout << "错误: WinDivert 组件部署失败" << endl;
        Logger::close();
        system("pause");
        return 1;
    }
    cout << "✓ WinDivert 文件已部署" << endl;

    // 动态加载 WinDivert.dll（从临时目录）
    cout << "正在加载 WinDivert.dll..." << endl;
    if (!LoadWinDivert(dll_path.c_str())) {
        cout << "错误: 无法加载 WinDivert.dll" << endl;
        Logger::error("LoadWinDivert() 失败: " + dll_path);
        Logger::close();
        system("pause");
        return 1;
    }
    cout << "✓ WinDivert 组件加载成功" << endl;
    cout << endl;

    cout << "============================================================" << endl;
    cout << "所有组件准备完毕，启动代理客户端..." << endl;
    cout << "============================================================" << endl;
    cout << endl;

    TCPProxyClient client(GAME_SERVER_IP, TUNNEL_SERVER_IP, TUNNEL_PORT, SECONDARY_IP);

    if (!client.start()) {
        Logger::error("客户端启动失败");
        Logger::close();
        system("pause");
        return 1;
    }

    cout << "✓ 代理客户端已启动" << endl;
    cout << endl;

    // ========== 步骤5: 启动握手测试 ==========
    cout << "[步骤5/5] 测试代理链路..." << endl;
    if (!test_tunnel_handshake(TUNNEL_SERVER_IP, TUNNEL_PORT)) {
        cout << endl;
        cout << "⚠ 警告: 握手测试失败！" << endl;
        cout << "可能的原因:" << endl;
        cout << "  1. 隧道服务器未启动或网络不通" << endl;
        cout << "  2. 防火墙阻止了连接" << endl;
        cout << "  3. 服务器地址或端口配置错误" << endl;
        cout << endl;
        cout << "您可以:" << endl;
        cout << "  - 按任意键继续运行(可能无法正常工作)" << endl;
        cout << "  - 或按Ctrl+C退出并检查网络/服务器配置" << endl;
        cout << endl;
        Logger::warning("握手测试失败，但允许继续运行");
        system("pause");
    } else {
        cout << "✓ 代理链路测试通过" << endl;
    }

    cout << endl;
    cout << "============================================================" << endl;
    cout << "✓ 系统就绪！现在可以启动游戏了" << endl;
    cout << "============================================================" << endl;
    cout << endl;
    cout << "按Ctrl+C退出..." << endl;
    client.wait();

    Logger::close();
    return 0;
}
