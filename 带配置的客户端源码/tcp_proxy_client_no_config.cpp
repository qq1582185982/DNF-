/*
 * DNF游戏代理客户端 - C++ 版本 v5.0 (无硬编码配置)
 * 从自身exe末尾读取配置
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

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

// 注意: 不再静态链接 WinDivert.lib，改用动态加载（windivert_loader.h）
// 这样程序启动时不会检查 WinDivert.dll 依赖，给自解压代码释放文件的机会

// 包含嵌入式 WinDivert 文件
#include "embedded_windivert.h"

using namespace std;

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

// ==================== 主客户端类 ====================
class TCPProxyClient {
private:
    string game_server_ip;
    string tunnel_server_ip;
    uint16_t tunnel_port;

    HANDLE windivert_handle;
    atomic<bool> running;

    int conn_id_counter;
    map<tuple<string, uint16_t, uint16_t>, TCPConnection*> connections;
    mutex conn_lock;

public:
    TCPProxyClient(const string& game_ip, const string& tunnel_ip, uint16_t tport)
        : game_server_ip(game_ip), tunnel_server_ip(tunnel_ip), tunnel_port(tport),
          windivert_handle(NULL), running(false),
          conn_id_counter(1) {
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

        lock_guard<mutex> lock(conn_lock);
        for (auto& pair : connections) {
            pair.second->stop();
            delete pair.second;
        }
        connections.clear();

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
                                 payload, payload_len);
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
                          const uint8_t* payload, int payload_len) {
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

        Logger::debug("[🔍拦截UDP] " + to_string(src_port) + "→" + to_string(dst_port) +
                   " 载荷=" + to_string(payload_len) + "字节" +
                   (payload_len > 0 ? "\n                    " + hex_dump : ""));

        // TODO: 如果需要转发UDP，这里添加转发逻辑
        // 目前只记录日志，不转发
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
    cout << "DNF游戏代理客户端 v5.0 (C++ 版本 - TCP)" << endl;
    cout << "编译时间: " << __DATE__ << " " << __TIME__ << endl;
    cout << "============================================================" << endl;
    cout << endl;

    // 自动部署 WinDivert 文件到临时目录
    cout << "正在部署 WinDivert 组件..." << endl;
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

    // 从exe末尾读取配置
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

    cout << "已读取配置:" << endl;
    cout << "  游戏服务器: " << GAME_SERVER_IP << endl;
    cout << "  隧道服务器: " << TUNNEL_SERVER_IP << ":" << TUNNEL_PORT << endl;
    cout << endl;

    TCPProxyClient client(GAME_SERVER_IP, TUNNEL_SERVER_IP, TUNNEL_PORT);

    if (!client.start()) {
        Logger::error("客户端启动失败");
        Logger::close();
        system("pause");
        return 1;
    }

    cout << "按Ctrl+C退出..." << endl;
    client.wait();

    Logger::close();
    return 0;
}
