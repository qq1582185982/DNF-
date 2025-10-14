/*
 * DNF 隧道服务器 - C++ 版本 v3.3
 * 完全按照Python版本架构重写
 * 支持 TCP + UDP 双协议转发
 * 支持多端口/多游戏服务器
 * 编译: g++ -O2 -pthread tcp_tunnel_server.cpp -o dnf-tunnel-server
 * 静态编译: g++ -O2 -static -pthread tcp_tunnel_server.cpp -o dnf-tunnel-server
 */

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

using namespace std;

// ==================== UDP伪造源IP辅助函数(前向声明) ====================
// 计算IP/UDP校验和
uint16_t calculate_checksum(uint16_t *data, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t*)data;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

// 前向声明Logger类
class Logger;

// ==================== 配置 ====================
// 单个服务器配置
struct ServerConfig {
    string name = "默认服务器";
    int listen_port = 33223;
    string game_server_ip = "192.168.2.110";
    int max_connections = 100;
};

// 全局配置
struct GlobalConfig {
    vector<ServerConfig> servers;
    string log_level = "INFO";
};

// ==================== 日志工具 ====================
class Logger {
private:
    static ofstream log_file;
    static mutex log_mutex;
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
            // 不能在这里调用log()因为会死锁，直接输出
            auto now = chrono::system_clock::now();
            auto time = chrono::system_clock::to_time_t(now);
            auto ms = chrono::duration_cast<chrono::milliseconds>(
                now.time_since_epoch()) % 1000;

            stringstream ss;
            ss << put_time(localtime(&time), "%Y-%m-%d %H:%M:%S")
               << "." << setfill('0') << setw(3) << ms.count()
               << " [INFO] 日志文件已初始化: " << filename;

            string log_line = ss.str();
            cout << log_line << endl;
            log_file << log_line << endl;
            log_file.flush();
        } else {
            cerr << "警告: 无法打开日志文件: " << filename << endl;
        }
    }

    static void close() {
        lock_guard<mutex> lock(log_mutex);
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

        auto now = chrono::system_clock::now();
        auto time = chrono::system_clock::to_time_t(now);
        auto ms = chrono::duration_cast<chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        stringstream ss;
        ss << put_time(localtime(&time), "%Y-%m-%d %H:%M:%S")
           << "." << setfill('0') << setw(3) << ms.count()
           << " [" << level << "] " << msg;

        string log_line = ss.str();

        // 输出到控制台和文件
        lock_guard<mutex> lock(log_mutex);
        cout << log_line << endl;
        if (file_enabled && log_file.is_open()) {
            log_file << log_line << endl;
            log_file.flush();  // 立即刷新，确保日志写入
        }
    }
};

// 静态成员初始化
ofstream Logger::log_file;
mutex Logger::log_mutex;
bool Logger::file_enabled = false;
string Logger::current_log_level = "INFO";

// ==================== UDP伪造源IP发送函数 ====================
// 使用Raw Socket伪造源IP发送UDP数据包
// client_ip: 真实客户端IP (伪造的源IP)
// client_port: 客户端端口
// game_ip: 游戏服务器IP (目标IP)
// game_port: 游戏服务器端口
// payload: UDP载荷数据
bool send_udp_spoofed(const string& client_ip, uint16_t client_port,
                      const string& game_ip, uint16_t game_port,
                      const uint8_t* payload, size_t payload_len) {
    try {
        // 创建Raw Socket
        int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_sock < 0) {
            Logger::error("[Raw Socket] 创建失败 (errno=" + to_string(errno) +
                        ": " + strerror(errno) + ") - 需要root权限!");
            return false;
        }

        // 设置IP_HDRINCL，告诉内核我们自己构造IP头
        int one = 1;
        if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            Logger::error("[Raw Socket] 设置IP_HDRINCL失败");
            close(raw_sock);
            return false;
        }

        // 构造完整数据包: IP头(20) + UDP头(8) + 载荷
        size_t total_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_len;
        uint8_t packet[total_len];
        memset(packet, 0, total_len);

        // ===== 构造IP头 =====
        struct ip* ip_hdr = (struct ip*)packet;
        ip_hdr->ip_hl = 5;                          // 头长度(5*4=20字节)
        ip_hdr->ip_v = 4;                           // IPv4
        ip_hdr->ip_tos = 0;                         // 服务类型
        ip_hdr->ip_len = htons(total_len);          // 总长度
        ip_hdr->ip_id = htons(rand() % 65535);      // 标识符
        ip_hdr->ip_off = 0;                         // 片偏移
        ip_hdr->ip_ttl = 64;                        // TTL
        ip_hdr->ip_p = IPPROTO_UDP;                 // 协议=UDP
        ip_hdr->ip_sum = 0;                         // 校验和(稍后计算)
        inet_pton(AF_INET, client_ip.c_str(), &ip_hdr->ip_src);  // 源IP(伪造!)
        inet_pton(AF_INET, game_ip.c_str(), &ip_hdr->ip_dst);    // 目标IP

        // 计算IP头校验和
        ip_hdr->ip_sum = calculate_checksum((uint16_t*)ip_hdr, sizeof(struct ip));

        // ===== 构造UDP头 =====
        struct udphdr* udp_hdr = (struct udphdr*)(packet + sizeof(struct ip));
        udp_hdr->source = htons(client_port);                     // 源端口
        udp_hdr->dest = htons(game_port);                         // 目标端口
        udp_hdr->len = htons(sizeof(struct udphdr) + payload_len); // UDP长度
        udp_hdr->check = 0;                                       // 校验和(可选,设为0)

        // 复制UDP载荷
        memcpy(packet + sizeof(struct ip) + sizeof(struct udphdr), payload, payload_len);

        // UDP校验和计算(使用伪头部)
        // 为了简化,这里设为0(大多数情况下可选)
        // 如需精确计算,需要构造UDP伪头部(源IP+目标IP+协议+UDP长度)

        // 发送数据包
        struct sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(game_port);
        inet_pton(AF_INET, game_ip.c_str(), &dest_addr.sin_addr);

        int sent = sendto(raw_sock, packet, total_len, 0,
                         (struct sockaddr*)&dest_addr, sizeof(dest_addr));

        close(raw_sock);

        if (sent < 0) {
            Logger::error("[Raw Socket] sendto失败 (errno=" + to_string(errno) +
                        ": " + strerror(errno) + ")");
            return false;
        }

        Logger::debug("[Raw Socket] 成功伪造源IP发送: " + client_ip + ":" +
                     to_string(client_port) + " -> " + game_ip + ":" +
                     to_string(game_port) + " (" + to_string(payload_len) + "字节)");
        return true;

    } catch (exception& e) {
        Logger::error("[Raw Socket] 异常: " + string(e.what()));
        return false;
    }
}

// ==================== TCP 连接管理 ====================
class TunnelConnection {
private:
    int conn_id;
    int client_fd;
    int game_fd;
    string game_server_ip;
    int game_port;
    atomic<bool> running;

    // UDP相关
    map<int, int> udp_sockets;  // dst_port -> udp_socket
    mutex udp_mutex;

    // 线程
    thread* client_to_game_thread;
    thread* game_to_client_thread;
    map<int, thread*> udp_threads;

public:
    TunnelConnection(int cid, int cfd, const string& game_ip, int gport)
        : conn_id(cid), client_fd(cfd), game_fd(-1),
          game_server_ip(game_ip), game_port(gport),
          running(false), client_to_game_thread(nullptr),
          game_to_client_thread(nullptr) {
        Logger::debug("[连接" + to_string(conn_id) + "] TunnelConnection对象已创建");
    }

    ~TunnelConnection() {
        Logger::debug("[连接" + to_string(conn_id) + "] 开始销毁TunnelConnection对象");
        stop();

        if (client_to_game_thread) {
            if (client_to_game_thread->joinable()) {
                Logger::debug("[连接" + to_string(conn_id) + "] 等待客户端→游戏线程结束");
                client_to_game_thread->join();
            }
            delete client_to_game_thread;
        }

        if (game_to_client_thread) {
            if (game_to_client_thread->joinable()) {
                Logger::debug("[连接" + to_string(conn_id) + "] 等待游戏→客户端线程结束");
                game_to_client_thread->join();
            }
            delete game_to_client_thread;
        }

        for (auto& pair : udp_threads) {
            if (pair.second && pair.second->joinable()) {
                Logger::debug("[连接" + to_string(conn_id) + "|UDP:" + to_string(pair.first) + "] 等待UDP线程结束");
                pair.second->join();
            }
            delete pair.second;
        }

        if (game_fd >= 0) {
            Logger::debug("[连接" + to_string(conn_id) + "] 关闭游戏服务器socket");
            close(game_fd);
        }
        if (client_fd >= 0) {
            Logger::debug("[连接" + to_string(conn_id) + "] 关闭客户端socket");
            close(client_fd);
        }

        for (auto& pair : udp_sockets) {
            if (pair.second >= 0) {
                Logger::debug("[连接" + to_string(conn_id) + "|UDP:" + to_string(pair.first) + "] 关闭UDP socket");
                close(pair.second);
            }
        }

        Logger::debug("[连接" + to_string(conn_id) + "] TunnelConnection对象已销毁");
    }

    bool start() {
        try {
            Logger::debug("[连接" + to_string(conn_id) + "] 开始启动连接");

            // 使用 getaddrinfo() 解析游戏服务器地址（支持域名/IPv4/IPv6）
            struct addrinfo hints{}, *result = nullptr, *rp = nullptr;
            hints.ai_family = AF_UNSPEC;      // 允许IPv4或IPv6
            hints.ai_socktype = SOCK_STREAM;  // TCP socket
            hints.ai_flags = 0;
            hints.ai_protocol = IPPROTO_TCP;

            string port_str = to_string(game_port);
            int ret = getaddrinfo(game_server_ip.c_str(), port_str.c_str(), &hints, &result);
            if (ret != 0) {
                Logger::error("[连接" + to_string(conn_id) + "] DNS解析失败: " +
                             game_server_ip + " (错误: " + gai_strerror(ret) + ")");
                return false;
            }

            Logger::debug("[连接" + to_string(conn_id) + "] DNS解析成功: " + game_server_ip);

            // 尝试连接所有解析结果
            int flag = 1;  // TCP_NODELAY标志
            for (rp = result; rp != nullptr; rp = rp->ai_next) {
                game_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (game_fd < 0) {
                    continue;
                }

                Logger::debug("[连接" + to_string(conn_id) + "] 游戏服务器socket已创建 fd=" +
                             to_string(game_fd) + " (协议: " +
                             (rp->ai_family == AF_INET ? "IPv4" : "IPv6") + ")");

                // 禁用Nagle算法
                setsockopt(game_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
                Logger::debug("[连接" + to_string(conn_id) + "] 已设置TCP_NODELAY");

                Logger::debug("[连接" + to_string(conn_id) + "] 正在连接游戏服务器 " +
                             game_server_ip + ":" + to_string(game_port));

                if (connect(game_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                    // 连接成功
                    Logger::debug("[连接" + to_string(conn_id) + "] 成功连接到游戏服务器");
                    break;
                }

                // 连接失败，关闭socket并尝试下一个地址
                Logger::debug("[连接" + to_string(conn_id) + "] 连接尝试失败 (errno=" +
                             to_string(errno) + ": " + strerror(errno) + ")，尝试下一个地址");
                close(game_fd);
                game_fd = -1;
            }

            freeaddrinfo(result);

            if (game_fd < 0 || rp == nullptr) {
                Logger::error("[连接" + to_string(conn_id) + "] 连接游戏服务器失败: " +
                             game_server_ip + ":" + to_string(game_port) + " (所有地址均失败)");
                return false;
            }

            // 客户端socket也禁用Nagle
            setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

            Logger::info("[连接" + to_string(conn_id) + "] 已连接到游戏服务器 " +
                        game_server_ip + ":" + to_string(game_port) + " (TCP_NODELAY)");

            running = true;

            // 启动双向转发线程（与Python版本完全一致）
            Logger::debug("[连接" + to_string(conn_id) + "] 启动客户端→游戏转发线程");
            client_to_game_thread = new thread([this]() {
                forward_client_to_game();
            });

            Logger::debug("[连接" + to_string(conn_id) + "] 启动游戏→客户端转发线程");
            game_to_client_thread = new thread([this]() {
                forward_game_to_client();
            });

            Logger::debug("[连接" + to_string(conn_id) + "] 连接启动完成，双向转发已开始");
            return true;

        } catch (exception& e) {
            Logger::error("[连接" + to_string(conn_id) + "] 启动失败: " + string(e.what()));
            return false;
        }
    }

    void stop() {
        running = false;
    }

    bool is_running() const {
        return running;
    }

private:
    // 完整实现sendall（确保所有数据发送完成）
    bool sendall(int fd, const uint8_t* data, int len) {
        int sent = 0;
        while (sent < len) {
            int ret = send(fd, data + sent, len - sent, 0);
            if (ret <= 0) {
                return false;
            }
            sent += ret;
        }
        return true;
    }

    // 线程1：转发客户端→游戏服务器（完全按照Python版本）
    void forward_client_to_game() {
        vector<uint8_t> buffer;
        uint8_t recv_buf[4096];  // 与Python版本一致

        Logger::debug("[连接" + to_string(conn_id) + "] 客户端→游戏转发线程已启动");

        try {
            while (running) {
                // recv(4096) - 与Python版本一致
                int n = recv(client_fd, recv_buf, sizeof(recv_buf), 0);
                if (n <= 0) {
                    if (n == 0) {
                        Logger::info("[连接" + to_string(conn_id) + "] 客户端正常断开 (recv返回0)");
                    } else {
                        int err = errno;
                        Logger::info("[连接" + to_string(conn_id) + "] 客户端连接错误 (recv返回" + to_string(n) +
                                   ", errno=" + to_string(err) + ": " + strerror(err) + ")");
                    }
                    running = false;
                    break;
                }

                Logger::debug("[连接" + to_string(conn_id) + "] 从客户端收到隧道数据 " + to_string(n) + "字节");

                // 添加到缓冲区
                buffer.insert(buffer.end(), recv_buf, recv_buf + n);

                // 解析协议：msg_type(1) + conn_id(4) + ...
                while (buffer.size() >= 5 && running) {
                    uint8_t msg_type = buffer[0];
                    uint32_t msg_conn_id = ntohl(*(uint32_t*)&buffer[1]);

                    if (msg_conn_id != (uint32_t)conn_id) {
                        Logger::warning("[连接" + to_string(conn_id) + "] 收到错误的连接ID: " +
                                      to_string(msg_conn_id));
                        running = false;
                        break;
                    }

                    if (msg_type == 0x01) {  // TCP数据消息
                        if (buffer.size() < 7) break;

                        uint16_t data_len = ntohs(*(uint16_t*)&buffer[5]);
                        if (buffer.size() < static_cast<size_t>(7 + data_len)) break;

                        // 提取payload
                        vector<uint8_t> payload(buffer.begin() + 7, buffer.begin() + 7 + data_len);
                        buffer.erase(buffer.begin(), buffer.begin() + 7 + data_len);

                        // 转发到游戏服务器 - sendall
                        if (!sendall(game_fd, payload.data(), payload.size())) {
                            int err = errno;
                            Logger::error("[连接" + to_string(conn_id) + "] 发送到游戏服务器失败 (errno=" +
                                        to_string(err) + ": " + strerror(err) + ")");

                            // 如果是EPIPE(32)或连接被重置，说明游戏socket已关闭
                            if (err == EPIPE || err == ECONNRESET || err == ENOTCONN) {
                                Logger::info("[连接" + to_string(conn_id) + "] 游戏socket已关闭，停止转发");
                                running = false;
                            }
                            break;
                        }

                        // 打印载荷预览（前16字节）
                        string hex_preview = "";
                        for (size_t i = 0; i < min((size_t)16, payload.size()); i++) {
                            char buf[4];
                            sprintf(buf, "%02x ", payload[i]);
                            hex_preview += buf;
                        }

                        Logger::debug("[连接" + to_string(conn_id) + "] 客户端→游戏: " +
                                    to_string(payload.size()) + "字节 载荷:" + hex_preview);
                    }
                    else if (msg_type == 0x02) {  // 窗口更新消息（暂不实现）
                        if (buffer.size() < 7) break;
                        buffer.erase(buffer.begin(), buffer.begin() + 7);
                    }
                    else if (msg_type == 0x03) {  // UDP消息
                        if (buffer.size() < 11) break;

                        uint16_t src_port = ntohs(*(uint16_t*)&buffer[5]);
                        uint16_t dst_port = ntohs(*(uint16_t*)&buffer[7]);
                        uint16_t data_len = ntohs(*(uint16_t*)&buffer[9]);

                        if (buffer.size() < static_cast<size_t>(11 + data_len)) break;

                        vector<uint8_t> payload(buffer.begin() + 11, buffer.begin() + 11 + data_len);
                        buffer.erase(buffer.begin(), buffer.begin() + 11 + data_len);

                        // 转发UDP数据
                        forward_udp_to_game(src_port, dst_port, payload);
                    }
                    else {
                        Logger::warning("[连接" + to_string(conn_id) + "] 未知消息类型: " +
                                      to_string((int)msg_type));
                        buffer.erase(buffer.begin(), buffer.begin() + 5);
                    }
                }
            }
        } catch (exception& e) {
            if (running) {
                Logger::error("[连接" + to_string(conn_id) + "] 客户端→游戏转发失败: " +
                            string(e.what()));
            }
            running = false;
        }
    }

    // 线程2：转发游戏服务器→客户端（完全按照Python版本）
    void forward_game_to_client() {
        uint8_t buffer[4096];  // 与Python版本一致

        Logger::debug("[连接" + to_string(conn_id) + "] 游戏→客户端转发线程已启动");

        int last_recv_size = 0;
        auto last_recv_time = chrono::system_clock::now();

        try {
            while (running) {
                // recv(4096) - 与Python版本一致
                int n = recv(game_fd, buffer, sizeof(buffer), 0);

                // ===== 关键诊断点：游戏服务器断开 =====
                if (n <= 0) {
                    auto now = chrono::system_clock::now();
                    auto time_since_last = chrono::duration_cast<chrono::milliseconds>(now - last_recv_time).count();

                    if (n == 0) {
                        Logger::info("[连接" + to_string(conn_id) + "] [!!!关键!!!] 游戏服务器发送FIN (recv返回0)");
                        Logger::info("[连接" + to_string(conn_id) + "] 最后一次接收: " + to_string(last_recv_size) +
                                   "字节，距今 " + to_string(time_since_last) + "ms");
                        Logger::info("[连接" + to_string(conn_id) + "] 执行半关闭：游戏→客户端方向关闭，客户端→游戏方向保持");
                    } else {
                        int err = errno;
                        Logger::error("[连接" + to_string(conn_id) + "] [!!!关键!!!] 游戏服务器连接错误");
                        Logger::error("[连接" + to_string(conn_id) + "] recv返回: " + to_string(n) +
                                    ", errno=" + to_string(err) + ": " + strerror(err));
                        Logger::error("[连接" + to_string(conn_id) + "] 最后一次接收: " + to_string(last_recv_size) +
                                    "字节，距今 " + to_string(time_since_last) + "ms");
                    }

                    // 半关闭：只关闭游戏socket的读取方向，不设置running=false
                    shutdown(game_fd, SHUT_RD);
                    Logger::debug("[连接" + to_string(conn_id) + "] 已关闭游戏socket读取方向(SHUT_RD)");
                    break;  // 只退出本线程，不影响客户端→游戏转发
                }

                // 记录接收时间和大小
                last_recv_time = chrono::system_clock::now();
                last_recv_size = n;

                // 打印载荷预览（前16字节）
                string hex_preview = "";
                for (int i = 0; i < min(16, n); i++) {
                    char buf[4];
                    sprintf(buf, "%02x ", buffer[i]);
                    hex_preview += buf;
                }

                Logger::debug("[连接" + to_string(conn_id) + "] 从游戏收到 " + to_string(n) +
                            "字节 载荷:" + hex_preview);

                // 封装协议：msg_type(1) + conn_id(4) + data_len(2) + payload
                uint8_t response[4096 + 7];
                response[0] = 0x01;
                *(uint32_t*)(response + 1) = htonl(conn_id);
                *(uint16_t*)(response + 5) = htons(n);
                memcpy(response + 7, buffer, n);

                // sendall - 确保完全发送
                if (!sendall(client_fd, response, 7 + n)) {
                    int err = errno;
                    Logger::error("[连接" + to_string(conn_id) + "] 发送到客户端失败 (errno=" +
                                to_string(err) + ": " + strerror(err) + ")");
                    running = false;
                    break;
                }

                Logger::debug("[连接" + to_string(conn_id) + "] 游戏→客户端: 已转发 " +
                            to_string(n) + "字节");
            }

            Logger::debug("[连接" + to_string(conn_id) + "] 游戏→客户端转发线程正常退出");

        } catch (exception& e) {
            if (running) {
                Logger::error("[连接" + to_string(conn_id) + "] 游戏→客户端转发异常: " +
                            string(e.what()));
            }
            running = false;
        }
    }

    // UDP转发到游戏服务器
    void forward_udp_to_game(uint16_t src_port, uint16_t dst_port, const vector<uint8_t>& data) {
        try {
            lock_guard<mutex> lock(udp_mutex);

            // 获取或创建UDP socket
            if (udp_sockets.find(dst_port) == udp_sockets.end()) {
                // 使用getaddrinfo解析游戏服务器地址
                struct addrinfo hints{}, *result = nullptr;
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;

                string port_str = to_string(dst_port);
                int ret = getaddrinfo(game_server_ip.c_str(), port_str.c_str(), &hints, &result);
                if (ret != 0 || result == nullptr) {
                    Logger::error("[连接" + to_string(conn_id) + "|UDP:" + to_string(dst_port) +
                                "] DNS解析失败: " + game_server_ip);
                    return;
                }

                int udp_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
                freeaddrinfo(result);

                if (udp_fd < 0) {
                    Logger::error("[连接" + to_string(conn_id) + "|UDP:" + to_string(dst_port) +
                                "] 创建UDP socket失败");
                    return;
                }
                udp_sockets[dst_port] = udp_fd;

                Logger::info("[连接" + to_string(conn_id) + "|UDP:" + to_string(dst_port) +
                           "] 创建UDP socket");

                // 启动UDP接收线程
                thread* t = new thread([this, dst_port, src_port]() {
                    recv_udp_from_game(dst_port, src_port);
                });
                udp_threads[dst_port] = t;
            }

            // 发送到游戏服务器 - 使用getaddrinfo解析地址
            int udp_fd = udp_sockets[dst_port];

            struct addrinfo hints{}, *result = nullptr;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;

            string port_str = to_string(dst_port);
            int ret = getaddrinfo(game_server_ip.c_str(), port_str.c_str(), &hints, &result);
            if (ret != 0 || result == nullptr) {
                Logger::error("[连接" + to_string(conn_id) + "|UDP:" + to_string(dst_port) +
                            "] DNS解析失败");
                return;
            }

            sendto(udp_fd, data.data(), data.size(), 0, result->ai_addr, result->ai_addrlen);
            freeaddrinfo(result);

            Logger::debug("[连接" + to_string(conn_id) + "|UDP:" + to_string(dst_port) +
                        "] 客户端→游戏: " + to_string(data.size()) + "字节");

        } catch (exception& e) {
            Logger::error("[连接" + to_string(conn_id) + "|UDP:" + to_string(dst_port) +
                        "] 转发失败: " + string(e.what()));
        }
    }

    // UDP从游戏服务器接收
    void recv_udp_from_game(int dst_port, int client_port) {
        try {
            int udp_fd;
            {
                lock_guard<mutex> lock(udp_mutex);
                if (udp_sockets.find(dst_port) == udp_sockets.end())
                    return;
                udp_fd = udp_sockets[dst_port];
            }

            uint8_t buffer[65535];
            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);

            while (running) {
                int n = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
                               (sockaddr*)&from_addr, &from_len);
                if (n <= 0) break;

                // 封装协议：msg_type(1) + conn_id(4) + src_port(2) + dst_port(2) + data_len(2) + payload
                uint8_t response[65535 + 11];
                response[0] = 0x03;
                *(uint32_t*)(response + 1) = htonl(conn_id);
                *(uint16_t*)(response + 5) = htons(dst_port);      // src_port（游戏服务器）
                *(uint16_t*)(response + 7) = htons(client_port);   // dst_port（游戏客户端）
                *(uint16_t*)(response + 9) = htons(n);            // data_len
                memcpy(response + 11, buffer, n);

                // sendall
                if (!sendall(client_fd, response, 11 + n)) {
                    Logger::error("[连接" + to_string(conn_id) + "|UDP:" + to_string(dst_port) +
                                "] 发送失败");
                    break;
                }

                Logger::debug("[连接" + to_string(conn_id) + "|UDP:" + to_string(dst_port) +
                            "] 游戏→客户端: " + to_string(n) + "字节");
            }
        } catch (exception& e) {
            Logger::error("[连接" + to_string(conn_id) + "|UDP] 接收线程异常: " +
                        string(e.what()));
        }
    }
};

// ==================== 隧道服务器 ====================
class TunnelServer {
private:
    ServerConfig config;
    string server_name;
    int listen_fd;
    map<string, TunnelConnection*> connections;  // key: "client_addr:conn_id"
    mutex conn_mutex;
    atomic<bool> running;

public:
    TunnelServer(const ServerConfig& cfg)
        : config(cfg), server_name(cfg.name), listen_fd(-1), running(false) {}

    ~TunnelServer() {
        stop();
        for (auto& pair : connections) {
            delete pair.second;
        }
    }

    bool start() {
        // 创建IPv6 socket（支持双栈：同时接受IPv4和IPv6连接）
        listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            Logger::error("[" + server_name + "] 创建socket失败");
            return false;
        }

        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        // 设置双栈模式：IPV6_V6ONLY=0 允许接受IPv4连接
        int v6only = 0;
        if (setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
            Logger::warning("[" + server_name + "] 设置双栈模式失败，将只支持IPv6");
        } else {
            Logger::debug("[" + server_name + "] 已启用IPv4/IPv6双栈模式");
        }

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;  // 监听所有IPv6地址（双栈模式下也监听IPv4）
        addr.sin6_port = htons(config.listen_port);

        if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
            Logger::error("[" + server_name + "] 绑定端口失败: " + to_string(config.listen_port));
            close(listen_fd);
            return false;
        }

        if (listen(listen_fd, config.max_connections) < 0) {
            Logger::error("[" + server_name + "] 监听失败");
            close(listen_fd);
            return false;
        }

        running = true;
        Logger::info("[" + server_name + "] 服务器启动成功，监听端口: " + to_string(config.listen_port) + " (IPv4/IPv6双栈)");
        Logger::info("[" + server_name + "] 游戏服务器: " + config.game_server_ip);

        accept_loop();
        return true;
    }

    void stop() {
        running = false;
        if (listen_fd >= 0) {
            close(listen_fd);
            listen_fd = -1;
        }
    }

private:
    void accept_loop() {
        while (running) {
            sockaddr_storage client_addr{};  // 使用sockaddr_storage支持IPv4/IPv6
            socklen_t addr_len = sizeof(client_addr);

            int client_fd = accept(listen_fd, (sockaddr*)&client_addr, &addr_len);
            if (client_fd < 0) {
                if (running) {
                    Logger::error("接受连接失败");
                }
                continue;
            }

            // 提取客户端IP地址（支持IPv4和IPv6）
            char client_ip[INET6_ADDRSTRLEN];
            int client_port = 0;
            string client_str;

            if (client_addr.ss_family == AF_INET) {
                // IPv4客户端
                sockaddr_in* addr_in = (sockaddr_in*)&client_addr;
                inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, INET6_ADDRSTRLEN);
                client_port = ntohs(addr_in->sin_port);
                client_str = string(client_ip) + ":" + to_string(client_port);
            } else if (client_addr.ss_family == AF_INET6) {
                // IPv6客户端
                sockaddr_in6* addr_in6 = (sockaddr_in6*)&client_addr;
                inet_ntop(AF_INET6, &addr_in6->sin6_addr, client_ip, INET6_ADDRSTRLEN);
                client_port = ntohs(addr_in6->sin6_port);
                client_str = "[" + string(client_ip) + "]:" + to_string(client_port);
            } else {
                client_str = "unknown";
            }

            Logger::info("新客户端连接: " + client_str);

            // 在新线程中处理客户端
            thread([this, client_fd, client_str]() {
                handle_client(client_fd, client_str);
            }).detach();
        }
    }

    void handle_client(int client_fd, const string& client_str) {
        try {
            // 接收握手：conn_id(4) + dst_port(2)
            uint8_t handshake[6];
            int n = recv(client_fd, handshake, 6, MSG_WAITALL);

            if (n != 6) {
                Logger::error("客户端 " + client_str + " 握手失败");
                close(client_fd);
                return;
            }

            // ===== 调试日志:打印原始握手数据 =====
            char hex_buf[100];
            sprintf(hex_buf, "%02x %02x %02x %02x %02x %02x",
                    handshake[0], handshake[1], handshake[2],
                    handshake[3], handshake[4], handshake[5]);
            Logger::debug("[握手] 收到握手数据(hex): " + string(hex_buf));

            uint32_t conn_id = ntohl(*(uint32_t*)handshake);
            uint16_t dst_port = ntohs(*(uint16_t*)(handshake + 4));

            char conn_id_hex[20];
            sprintf(conn_id_hex, "0x%08x", conn_id);
            Logger::debug("[握手] 解析结果: conn_id=" + to_string(conn_id) +
                        " (" + string(conn_id_hex) + "), dst_port=" + to_string(dst_port));

            // ===== 关键修改：识别UDP tunnel连接 =====
            const uint32_t UDP_MAGIC = 0xFFFFFFFF;

            Logger::debug("[握手] 判断UDP Tunnel: conn_id=" + to_string(conn_id) +
                        ", UDP_MAGIC=" + to_string(UDP_MAGIC) +
                        ", 相等?" + (conn_id == UDP_MAGIC ? "YES" : "NO"));

            if (conn_id == UDP_MAGIC) {
                Logger::info("[UDP Tunnel] ✓ 识别为UDP Tunnel连接!");
                Logger::info("[UDP Tunnel] 收到UDP握手请求: 客户端=" + client_str +
                           ", 游戏端口=" + to_string(dst_port));

                // 发送UDP握手确认响应(与TCP握手相同的6字节格式)
                uint8_t ack[6];
                *(uint32_t*)ack = htonl(0xFFFFFFFF);  // conn_id=0xFFFFFFFF表示握手确认
                *(uint16_t*)(ack + 4) = htons(dst_port);  // 回传端口

                if (send(client_fd, ack, 6, 0) != 6) {
                    Logger::error("[UDP Tunnel] 发送握手确认失败");
                    close(client_fd);
                    return;
                }

                Logger::info("[UDP Tunnel] 握手成功,已发送确认");
                Logger::info("[UDP Tunnel] 调用 handle_udp_tunnel()");
                handle_udp_tunnel(client_fd, client_str, dst_port);
                Logger::info("[UDP Tunnel] handle_udp_tunnel()函数已返回");
                return;
            }

            Logger::debug("[握手] ✗ 不是UDP Tunnel,按普通TCP连接处理");
            Logger::info("[连接" + to_string(conn_id) + "] 握手成功: 目标端口=" +
                        to_string(dst_port) + ", 客户端=" + client_str);

            // 创建连接对象
            TunnelConnection* conn = new TunnelConnection(
                conn_id, client_fd, config.game_server_ip, dst_port
            );

            string conn_key = client_str + ":" + to_string(conn_id);
            {
                lock_guard<mutex> lock(conn_mutex);
                connections[conn_key] = conn;
            }

            // 启动连接（启动双向转发线程）
            if (!conn->start()) {
                lock_guard<mutex> lock(conn_mutex);
                connections.erase(conn_key);
                delete conn;
                return;
            }

            // 等待连接结束
            while (conn->is_running()) {
                this_thread::sleep_for(chrono::seconds(1));
            }

            // 清理
            {
                lock_guard<mutex> lock(conn_mutex);
                connections.erase(conn_key);
            }
            delete conn;

        } catch (exception& e) {
            Logger::error("处理客户端 " + client_str + " 时出错: " + string(e.what()));
            close(client_fd);
        }
    }

    // 处理UDP tunnel连接
    void handle_udp_tunnel(int client_fd, const string& client_str, uint16_t game_port) {
        try {
            // 提取客户端真实IP地址(用于伪造源IP)
            string real_client_ip;

            // 处理IPv6格式: [xxxx]:port 或 IPv4格式: x.x.x.x:port
            if (client_str.front() == '[') {
                // IPv6格式: [xxxx]:port
                // 找到最后一个']'的位置
                size_t bracket_end = client_str.find(']');
                if (bracket_end != string::npos) {
                    // 提取方括号内的内容
                    string ip_with_brackets = client_str.substr(0, bracket_end + 1);
                    // 去掉方括号
                    real_client_ip = ip_with_brackets.substr(1, ip_with_brackets.length() - 2);

                    // 检查是否是IPv6映射的IPv4地址 (::ffff:x.x.x.x)
                    if (real_client_ip.find("::ffff:") == 0) {
                        // 提取IPv4部分
                        real_client_ip = real_client_ip.substr(7);  // 去掉"::ffff:"前缀
                    }
                } else {
                    // 格式错误,使用整个字符串
                    real_client_ip = client_str;
                }
            } else {
                // 纯IPv4格式: x.x.x.x:port
                size_t colon_pos = client_str.find(":");
                if (colon_pos != string::npos) {
                    real_client_ip = client_str.substr(0, colon_pos);
                } else {
                    real_client_ip = client_str;
                }
            }

            Logger::info("[UDP Tunnel] 开始处理UDP代理连接");
            Logger::info("[UDP Tunnel] 客户端字符串: " + client_str);
            Logger::info("[UDP Tunnel] 真实客户端IP: " + real_client_ip + " (将用于伪造源IP)");

            // UDP连接映射: remote_port -> udp_socket
            map<uint16_t, int> udp_sockets;
            map<uint16_t, thread*> udp_recv_threads;
            // 存储每个UDP socket对应的conn_id和客户端端口
            struct SocketMetadata {
                uint32_t conn_id;
                uint16_t client_port;
            };
            map<uint16_t, SocketMetadata> socket_metadata;  // dst_port -> {conn_id, src_port}
            mutex udp_mutex;
            mutex send_mutex;  // 保护client_fd的send操作,防止多线程竞争
            atomic<bool> running(true);

            // 创建UDP接收线程的lambda函数
            auto create_udp_receiver = [&](uint16_t remote_port) -> thread* {
                return new thread([&, remote_port, client_fd]() {
                    try {
                        int udp_fd;
                        uint32_t conn_id;
                        uint16_t client_port;

                        {
                            lock_guard<mutex> lock(udp_mutex);
                            if (udp_sockets.find(remote_port) == udp_sockets.end()) {
                                return;
                            }
                            udp_fd = udp_sockets[remote_port];

                            // 获取元数据
                            auto meta_it = socket_metadata.find(remote_port);
                            if (meta_it == socket_metadata.end()) {
                                Logger::error("[UDP Tunnel|" + to_string(remote_port) +
                                            "] 未找到socket元数据");
                                return;
                            }
                            conn_id = meta_it->second.conn_id;
                            client_port = meta_it->second.client_port;
                        }

                        uint8_t buffer[65535];
                        sockaddr_storage from_addr{};
                        socklen_t from_len = sizeof(from_addr);

                        Logger::info("[UDP Tunnel|" + to_string(remote_port) + "] 接收线程已启动 (conn_id=" +
                                    to_string(conn_id) + ", client_port=" + to_string(client_port) + ")");

                        while (running) {
                            Logger::info("[UDP Tunnel|" + to_string(remote_port) + "] 等待从游戏服务器接收UDP数据...");

                            int n = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
                                           (sockaddr*)&from_addr, &from_len);

                            if (n <= 0) {
                                int err = errno;
                                Logger::info("[UDP Tunnel|" + to_string(remote_port) +
                                           "] recvfrom返回: n=" + to_string(n) +
                                           ", errno=" + to_string(err) + " (" + strerror(err) + ")");
                                break;
                            }

                            Logger::info("[UDP Tunnel|" + to_string(remote_port) +
                                        "] ←[游戏服务器] 接收到UDP数据: " + to_string(n) + "字节");

                            // 打印接收到的UDP payload hex dump
                            string payload_hex = "";
                            for (int i = 0; i < n; i++) {
                                if (i > 0 && i % 16 == 0) {
                                    payload_hex += "\n                    ";
                                }
                                char hex_buf[4];
                                sprintf(hex_buf, "%02x ", buffer[i]);
                                payload_hex += hex_buf;
                            }
                            Logger::info("[UDP Tunnel|" + to_string(remote_port) +
                                        "] UDP Payload(" + to_string(n) + "字节):\n                    " + payload_hex);

                            // 封装协议：msg_type(1) + conn_id(4) + src_port(2) + dst_port(2) + data_len(2) + payload
                            vector<uint8_t> response(11 + n);
                            response[0] = 0x03;  // msg_type=UDP
                            *(uint32_t*)(&response[1]) = htonl(conn_id);        // 使用正确的conn_id
                            *(uint16_t*)(&response[5]) = htons(remote_port);     // src_port（游戏服务器）
                            *(uint16_t*)(&response[7]) = htons(client_port);     // dst_port（客户端端口）
                            *(uint16_t*)(&response[9]) = htons(n);              // data_len
                            memcpy(&response[11], buffer, n);

                            // 打印封装后的完整response数据包
                            string response_hex = "";
                            int dump_len = min(28, (int)response.size());  // 打印前28字节(协议头11+部分payload)
                            for (int i = 0; i < dump_len; i++) {
                                if (i > 0 && i % 16 == 0) {
                                    response_hex += "\n                    ";
                                }
                                char hex_buf[4];
                                sprintf(hex_buf, "%02x ", response[i]);
                                response_hex += hex_buf;
                            }
                            Logger::info("[UDP Tunnel|" + to_string(remote_port) +
                                        "] 封装后数据包(前" + to_string(dump_len) + "字节):\n                    " + response_hex);

                            // 发送到客户端 - 使用互斥锁保护,防止多线程同时send()导致数据损坏
                            {
                                lock_guard<mutex> lock(send_mutex);
                                Logger::info("[UDP Tunnel|" + to_string(remote_port) +
                                           "] →[客户端] 准备发送: " + to_string(response.size()) +
                                           "字节 (client_fd=" + to_string(client_fd) +
                                           ", conn_id=" + to_string(conn_id) + ")");

                                int sent = 0;
                                while (sent < (int)response.size() && running) {
                                    int ret = send(client_fd, response.data() + sent,
                                                 response.size() - sent, 0);

                                    Logger::info("[UDP Tunnel|" + to_string(remote_port) +
                                               "] send()返回: " + to_string(ret) +
                                               " (已发送: " + to_string(sent) +
                                               "/" + to_string(response.size()) + "字节)");

                                    if (ret <= 0) {
                                        int err = errno;
                                        Logger::error("[UDP Tunnel|" + to_string(remote_port) +
                                                    "] send()失败: 返回值=" + to_string(ret) +
                                                    ", errno=" + to_string(err) + " (" + strerror(err) + ")");
                                        running = false;
                                        break;
                                    }
                                    sent += ret;
                                }

                                if (sent == (int)response.size()) {
                                    Logger::info("[UDP Tunnel|" + to_string(remote_port) +
                                                "] ✓ 成功发送到客户端: " + to_string(response.size()) +
                                                "字节 (conn_id=" + to_string(conn_id) + ")");
                                } else {
                                    Logger::error("[UDP Tunnel|" + to_string(remote_port) +
                                                "] ✗ 发送不完整: 仅发送 " + to_string(sent) +
                                                "/" + to_string(response.size()) + "字节");
                                }
                            }
                        }

                        Logger::info("[UDP Tunnel|" + to_string(remote_port) + "] 接收线程退出");
                    } catch (exception& e) {
                        Logger::error("[UDP Tunnel] 接收线程异常: " + string(e.what()));
                    }
                });
            };

            // 主循环：接收客户端的UDP数据
            vector<uint8_t> buffer;
            uint8_t recv_buf[4096];

            Logger::info("[UDP Tunnel] 进入UDP转发循环 (client_fd=" + to_string(client_fd) + ")");

            while (running) {
                Logger::debug("[UDP Tunnel] 等待从客户端接收数据...");

                int n = recv(client_fd, recv_buf, sizeof(recv_buf), 0);

                if (n <= 0) {
                    int err = errno;
                    if (n == 0) {
                        Logger::info("[UDP Tunnel] 客户端正常断开 (recv返回0)");
                    } else {
                        Logger::error("[UDP Tunnel] 客户端连接错误 (recv返回" + to_string(n) +
                                    ", errno=" + to_string(err) + ": " + strerror(err) + ")");
                    }
                    break;
                }

                Logger::info("[UDP Tunnel] ←[客户端] 收到 " + to_string(n) + "字节");

                // 添加到缓冲区
                buffer.insert(buffer.end(), recv_buf, recv_buf + n);

                // 解析协议：msg_type(1) + conn_id(4) + src_port(2) + dst_port(2) + data_len(2) + payload
                while (buffer.size() >= 11 && running) {
                    uint8_t msg_type = buffer[0];
                    uint32_t msg_conn_id = ntohl(*(uint32_t*)&buffer[1]);
                    uint16_t src_port = ntohs(*(uint16_t*)&buffer[5]);
                    uint16_t dst_port = ntohs(*(uint16_t*)&buffer[7]);
                    uint16_t data_len = ntohs(*(uint16_t*)&buffer[9]);

                    // 检查数据是否完整
                    if (buffer.size() < static_cast<size_t>(11 + data_len)) {
                        break;
                    }

                    if (msg_type != 0x03) {
                        Logger::warning("[UDP Tunnel] 未知消息类型: " + to_string((int)msg_type));
                        buffer.erase(buffer.begin(), buffer.begin() + 1);
                        continue;
                    }

                    // 提取payload
                    vector<uint8_t> payload(buffer.begin() + 11, buffer.begin() + 11 + data_len);
                    buffer.erase(buffer.begin(), buffer.begin() + 11 + data_len);

                    Logger::debug("[UDP Tunnel] 解析: conn_id=" + to_string(msg_conn_id) +
                                ", src=" + to_string(src_port) + ", dst=" + to_string(dst_port) +
                                ", len=" + to_string(data_len));

                    // 获取或创建UDP socket
                    {
                        lock_guard<mutex> lock(udp_mutex);
                        if (udp_sockets.find(dst_port) == udp_sockets.end()) {
                            // 解析游戏服务器地址
                            struct addrinfo hints{}, *result = nullptr;
                            hints.ai_family = AF_UNSPEC;
                            hints.ai_socktype = SOCK_DGRAM;
                            hints.ai_protocol = IPPROTO_UDP;

                            string port_str = to_string(dst_port);
                            int ret = getaddrinfo(config.game_server_ip.c_str(), port_str.c_str(),
                                                &hints, &result);
                            if (ret != 0 || result == nullptr) {
                                Logger::error("[UDP Tunnel|" + to_string(dst_port) +
                                            "] DNS解析失败: " + config.game_server_ip);
                                continue;
                            }

                            int udp_fd = socket(result->ai_family, result->ai_socktype,
                                              result->ai_protocol);
                            if (udp_fd < 0) {
                                Logger::error("[UDP Tunnel|" + to_string(dst_port) +
                                            "] 创建UDP socket失败");
                                freeaddrinfo(result);
                                continue;
                            }

                            udp_sockets[dst_port] = udp_fd;
                            freeaddrinfo(result);

                            // **关键修复**: 必须在启动接收线程之前保存元数据
                            socket_metadata[dst_port] = {msg_conn_id, src_port};

                            Logger::info("[UDP Tunnel|" + to_string(dst_port) + "] 创建UDP socket (conn_id=" +
                                       to_string(msg_conn_id) + ", client_port=" + to_string(src_port) + ")");

                            // 启动UDP接收线程 (此时元数据已就绪)
                            thread* t = create_udp_receiver(dst_port);
                            udp_recv_threads[dst_port] = t;
                        } else {
                            // Socket已存在,更新元数据(可能是新的UDP流使用同一目标端口)
                            socket_metadata[dst_port] = {msg_conn_id, src_port};
                            Logger::debug("[UDP Tunnel|" + to_string(dst_port) +
                                        "] 更新元数据 (conn_id=" + to_string(msg_conn_id) +
                                        ", client_port=" + to_string(src_port) + ")");
                        }
                    }

                    // ===== 关键修改: 使用Raw Socket伪造源IP发送UDP =====
                    Logger::info("[UDP Tunnel|" + to_string(dst_port) + "] 使用Raw Socket伪造源IP发送");

                    bool success = send_udp_spoofed(
                        real_client_ip,          // 伪造的源IP (真实客户端IP)
                        src_port,                // 源端口 (客户端端口)
                        config.game_server_ip,   // 目标IP (游戏服务器IP)
                        dst_port,                // 目标端口 (游戏服务器端口)
                        payload.data(),          // UDP载荷
                        payload.size()           // 载荷长度
                    );

                    if (success) {
                        Logger::info("[UDP Tunnel|" + to_string(dst_port) +
                                    "] ✓ 成功伪造源IP发送: " + real_client_ip + ":" + to_string(src_port) +
                                    " -> " + config.game_server_ip + ":" + to_string(dst_port) +
                                    " (" + to_string(payload.size()) + "字节)");
                    } else {
                        Logger::error("[UDP Tunnel|" + to_string(dst_port) +
                                     "] ✗ Raw Socket发送失败");
                    }
                }
            }

            // 清理
            running = false;
            Logger::info("[UDP Tunnel] 开始清理资源");

            // 等待所有UDP接收线程结束
            for (auto& pair : udp_recv_threads) {
                if (pair.second && pair.second->joinable()) {
                    Logger::debug("[UDP Tunnel|" + to_string(pair.first) + "] 等待接收线程结束");
                    pair.second->join();
                }
                delete pair.second;
            }

            // 关闭所有UDP sockets
            for (auto& pair : udp_sockets) {
                Logger::debug("[UDP Tunnel|" + to_string(pair.first) + "] 关闭UDP socket");
                close(pair.second);
            }

            close(client_fd);
            Logger::info("[UDP Tunnel] 连接已关闭");

        } catch (exception& e) {
            Logger::error("[UDP Tunnel] 异常: " + string(e.what()));
            close(client_fd);
        }
    }
};

// ==================== 辅助函数 ====================
int extract_number(const string& str) {
    string num_str;
    for (char c : str) {
        if (isdigit(c)) {
            num_str += c;
        }
    }
    if (num_str.empty()) return 0;

    try {
        return stoi(num_str);
    } catch (...) {
        return 0;
    }
}

// ==================== 配置文件加载 ====================
GlobalConfig load_config(const string& filename) {
    GlobalConfig global_config;

    ifstream file(filename);
    if (!file.is_open()) {
        Logger::warning("配置文件不存在: " + filename + "，使用默认配置");
        // 返回包含一个默认服务器的配置
        ServerConfig default_server;
        global_config.servers.push_back(default_server);
        return global_config;
    }

    string line;
    bool in_servers_array = false;
    bool in_server_object = false;
    ServerConfig current_server;

    while (getline(file, line)) {
        // 检查是否进入servers数组
        if (line.find("\"servers\"") != string::npos && line.find("[") != string::npos) {
            in_servers_array = true;
            continue;
        }

        // 检查是否退出servers数组
        if (in_servers_array && line.find("]") != string::npos) {
            string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            if (trimmed[0] == ']') {
                in_servers_array = false;
                continue;
            }
        }

        // 在servers数组中
        if (in_servers_array) {
            // 检查是否开始一个新的server对象
            if (line.find("{") != string::npos && !in_server_object) {
                in_server_object = true;
                current_server = ServerConfig();  // 重置为默认值
                continue;
            }

            // 检查是否结束当前server对象
            if (in_server_object && line.find("}") != string::npos) {
                string trimmed = line;
                trimmed.erase(0, trimmed.find_first_not_of(" \t"));
                if (trimmed[0] == '}') {
                    global_config.servers.push_back(current_server);
                    in_server_object = false;
                    continue;
                }
            }

            // 解析server对象内的字段
            if (in_server_object) {
                if (line.find("\"name\"") != string::npos) {
                    size_t start = line.find("\"", line.find(":")) + 1;
                    size_t end = line.find("\"", start);
                    if (start != string::npos && end != string::npos) {
                        current_server.name = line.substr(start, end - start);
                    }
                }
                else if (line.find("\"listen_port\"") != string::npos) {
                    size_t pos = line.find(":");
                    if (pos != string::npos) {
                        string value = line.substr(pos + 1);
                        int num = extract_number(value);
                        if (num > 0) current_server.listen_port = num;
                    }
                }
                else if (line.find("\"game_server_ip\"") != string::npos) {
                    size_t start = line.find("\"", line.find(":")) + 1;
                    size_t end = line.find("\"", start);
                    if (start != string::npos && end != string::npos) {
                        current_server.game_server_ip = line.substr(start, end - start);
                    }
                }
                else if (line.find("\"max_connections\"") != string::npos) {
                    size_t pos = line.find(":");
                    if (pos != string::npos) {
                        string value = line.substr(pos + 1);
                        int num = extract_number(value);
                        if (num > 0) current_server.max_connections = num;
                    }
                }
            }
        }

        // 解析全局log_level
        if (!in_servers_array && line.find("\"log_level\"") != string::npos) {
            size_t start = line.find("\"", line.find(":")) + 1;
            size_t end = line.find("\"", start);
            if (start != string::npos && end != string::npos) {
                global_config.log_level = line.substr(start, end - start);
            }
        }
    }

    // 如果没有解析到任何服务器，添加默认服务器
    if (global_config.servers.empty()) {
        Logger::warning("配置文件中未找到服务器配置，使用默认配置");
        ServerConfig default_server;
        global_config.servers.push_back(default_server);
    }

    return global_config;
}

// ==================== 生成默认配置文件 ====================
bool generate_default_config(const string& filename) {
    ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    file << "// ============================================================\n";
    file << "// DNF隧道服务器配置文件 v3.3\n";
    file << "// 支持多端口/多游戏服务器\n";
    file << "// ============================================================\n";
    file << "//\n";
    file << "// 配置说明:\n";
    file << "//\n";
    file << "// name             - 服务器名称（用于日志标识）\n";
    file << "// listen_port      - 隧道服务器监听端口（客户端连接此端口）\n";
    file << "//                    范围: 1-65535，建议使用 30000-40000\n";
    file << "//                    不同服务器必须使用不同端口\n";
    file << "//\n";
    file << "// game_server_ip   - 游戏服务器的内网IP地址\n";
    file << "//                    这是隧道服务器要转发到的目标服务器\n";
    file << "//\n";
    file << "// max_connections  - 最大并发连接数\n";
    file << "//                    根据服务器性能调整，建议 50-500\n";
    file << "//\n";
    file << "// log_level        - 全局日志级别: DEBUG, INFO, WARN, ERROR\n";
    file << "//                    生产环境建议使用 INFO\n";
    file << "//\n";
    file << "// ============================================================\n";
    file << "//\n";
    file << "// 配置示例:\n";
    file << "//\n";
    file << "// 示例1: 单个游戏服务器\n";
    file << "// {\n";
    file << "//   \"servers\": [\n";
    file << "//     {\n";
    file << "//       \"name\": \"游戏服1\",\n";
    file << "//       \"listen_port\": 33223,\n";
    file << "//       \"game_server_ip\": \"192.168.2.110\",\n";
    file << "//       \"max_connections\": 100\n";
    file << "//     }\n";
    file << "//   ],\n";
    file << "//   \"log_level\": \"INFO\"\n";
    file << "// }\n";
    file << "//\n";
    file << "// 示例2: 多个游戏服务器（推荐）\n";
    file << "// {\n";
    file << "//   \"servers\": [\n";
    file << "//     {\n";
    file << "//       \"name\": \"游戏服1\",\n";
    file << "//       \"listen_port\": 33223,\n";
    file << "//       \"game_server_ip\": \"192.168.2.110\",\n";
    file << "//       \"max_connections\": 100\n";
    file << "//     },\n";
    file << "//     {\n";
    file << "//       \"name\": \"游戏服2\",\n";
    file << "//       \"listen_port\": 33224,\n";
    file << "//       \"game_server_ip\": \"192.168.2.100\",\n";
    file << "//       \"max_connections\": 100\n";
    file << "//     },\n";
    file << "//     {\n";
    file << "//       \"name\": \"游戏服3\",\n";
    file << "//       \"listen_port\": 33225,\n";
    file << "//       \"game_server_ip\": \"192.168.2.11\",\n";
    file << "//       \"max_connections\": 100\n";
    file << "//     }\n";
    file << "//   ],\n";
    file << "//   \"log_level\": \"INFO\"\n";
    file << "// }\n";
    file << "//\n";
    file << "// ============================================================\n";
    file << "//\n";
    file << "// 注意事项:\n";
    file << "// 1. 一个程序可以管理多个游戏服务器\n";
    file << "// 2. 每个服务器必须使用不同的监听端口\n";
    file << "// 3. 服务器名称用于日志中区分不同服务器\n";
    file << "// 4. 所有服务器共享同一个日志文件\n";
    file << "// 5. 客户端连接时需要指定对应的端口号\n";
    file << "//\n";
    file << "// ============================================================\n";
    file << "\n";
    file << "{\n";
    file << "  \"servers\": [\n";
    file << "    {\n";
    file << "      \"name\": \"游戏服1\",\n";
    file << "      \"listen_port\": 33223,\n";
    file << "      \"game_server_ip\": \"192.168.2.110\",\n";
    file << "      \"max_connections\": 100\n";
    file << "    }\n";
    file << "  ],\n";
    file << "  \"log_level\": \"INFO\"\n";
    file << "}\n";

    file.close();
    return true;
}

// ==================== 主函数 ====================
int main() {
    // 创建log目录（如果不存在）
    mkdir("log", 0755);

    // 生成带时间戳的日志文件名
    auto now = chrono::system_clock::now();
    auto time = chrono::system_clock::to_time_t(now);
    stringstream log_filename;
    log_filename << "log/server_log_" << put_time(localtime(&time), "%Y%m%d_%H%M%S") << ".txt";

    // 初始化日志系统
    Logger::init(log_filename.str());

    cout << "============================================================" << endl;
    cout << "DNF多端口隧道服务器 v3.3 (C++ 版本 - Python架构)" << endl;
    cout << "支持 TCP + UDP 双协议转发 + 多游戏服务器" << endl;
    cout << "============================================================" << endl;
    cout << endl;

    const string config_file = "config.json";

    // 检查配置文件是否存在
    ifstream check_file(config_file);
    bool config_exists = check_file.is_open();
    check_file.close();

    if (!config_exists) {
        // 首次运行 - 生成配置文件并退出
        cout << "========================================" << endl;
        cout << "首次运行检测" << endl;
        cout << "========================================" << endl;
        cout << endl;

        Logger::info("未找到配置文件: " + config_file);
        Logger::info("正在生成默认配置文件...");

        if (generate_default_config(config_file)) {
            cout << "✓ 配置文件已生成: " << config_file << endl;
            cout << endl;
            cout << "请按照以下步骤配置服务器:" << endl;
            cout << "----------------------------------------" << endl;
            cout << "1. 编辑 " << config_file << " 文件" << endl;
            cout << "2. 在 servers 数组中配置游戏服务器:" << endl;
            cout << "   - name: 服务器名称（用于日志标识）" << endl;
            cout << "   - listen_port: 监听端口（不同服务器用不同端口）" << endl;
            cout << "   - game_server_ip: 游戏服务器IP地址" << endl;
            cout << "   - max_connections: 最大连接数" << endl;
            cout << "3. 可以配置多个服务器，一个程序管理所有" << endl;
            cout << "4. 保存文件后重新运行本程序" << endl;
            cout << "----------------------------------------" << endl;
            cout << endl;

            Logger::info("配置文件已生成，等待用户配置");
            Logger::info("程序退出，请修改配置后重新启动");
            Logger::close();
            return 0;  // 正常退出
        } else {
            cout << "✗ 生成配置文件失败" << endl;
            Logger::error("无法创建配置文件: " + config_file);
            Logger::close();
            return 1;  // 错误退出
        }
    }

    // 配置文件存在 - 正常加载
    GlobalConfig global_config = load_config(config_file);

    // 设置日志级别
    Logger::set_log_level(global_config.log_level);

    Logger::info("配置加载完成，共 " + to_string(global_config.servers.size()) + " 个服务器");
    Logger::info("日志级别: " + global_config.log_level);
    cout << endl;

    // 显示所有服务器配置
    for (size_t i = 0; i < global_config.servers.size(); i++) {
        const ServerConfig& srv = global_config.servers[i];
        Logger::info("[" + srv.name + "] 端口:" + to_string(srv.listen_port) +
                    " → " + srv.game_server_ip +
                    " (最大连接:" + to_string(srv.max_connections) + ")");
    }
    cout << endl;

    // 创建所有TunnelServer实例
    vector<TunnelServer*> servers;
    vector<thread*> server_threads;

    for (const ServerConfig& srv_cfg : global_config.servers) {
        TunnelServer* server = new TunnelServer(srv_cfg);
        servers.push_back(server);
    }

    Logger::info("正在启动所有隧道服务器...");

    // 在独立线程中启动每个服务器
    for (TunnelServer* server : servers) {
        thread* t = new thread([server]() {
            server->start();
        });
        server_threads.push_back(t);
    }

    Logger::info("所有隧道服务器已启动");
    cout << endl;
    cout << "服务器正在运行，按 Ctrl+C 停止..." << endl;
    cout << "============================================================" << endl;

    // 等待所有线程
    for (thread* t : server_threads) {
        if (t->joinable()) {
            t->join();
        }
    }

    // 清理
    for (thread* t : server_threads) {
        delete t;
    }
    for (TunnelServer* server : servers) {
        delete server;
    }

    Logger::close();
    return 0;
}
