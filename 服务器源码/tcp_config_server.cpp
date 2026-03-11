/*
 * TCP配置服务器
 * 提供服务器列表查询接口
 * 协议: 接收 "GET_SERVERS\n", 返回JSON字符串
 * 替代HTTP API，绕过备案限制
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sstream>
#include <vector>
#include <string>
#include <fstream>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <sys/inotify.h>
#include <sys/select.h>

#include "ip_pool_manager.h"

using namespace std;

// 前向声明
void* config_monitor_thread(void* arg);

// 服务器配置结构
struct ServerConfig {
    int id;
    string name;
    string game_server_ip;
    string tunnel_server_ip;
    int tunnel_port;
    string download_url;  // 客户端下载地址
    string virtual_subnet;
    string virtual_gateway;
    int lease_seconds;

    // 默认构造函数
    ServerConfig()
        : id(0),
          tunnel_port(0),
          lease_seconds((int)ip_tunnel::kDefaultLeaseSeconds) {}

    // 拷贝构造函数
    ServerConfig(const ServerConfig& other)
        : id(other.id),
          name(other.name),
          game_server_ip(other.game_server_ip),
          tunnel_server_ip(other.tunnel_server_ip),
          tunnel_port(other.tunnel_port),
          download_url(other.download_url),
          virtual_subnet(other.virtual_subnet),
          virtual_gateway(other.virtual_gateway),
          lease_seconds(other.lease_seconds) {}

    // 赋值运算符
    ServerConfig& operator=(const ServerConfig& other) {
        if (this != &other) {
            id = other.id;
            name = other.name;
            game_server_ip = other.game_server_ip;
            tunnel_server_ip = other.tunnel_server_ip;
            tunnel_port = other.tunnel_port;
            download_url = other.download_url;
            virtual_subnet = other.virtual_subnet;
            virtual_gateway = other.virtual_gateway;
            lease_seconds = other.lease_seconds;
        }
        return *this;
    }
};

// 全局变量
static vector<ServerConfig> g_servers;
static mutex g_servers_mutex;  // 保护服务器列表和IP池
static int g_api_port = 35000;
static volatile bool g_running = true;
static string g_config_file;  // 配置文件路径
static string g_tunnel_server_ip;  // 隧道服务器IP
static bool g_auto_reload = true;  // 自动重载开关
static pthread_t g_monitor_thread = 0;  // 配置监控线程ID
static IPPoolManager g_ip_pool_manager;

// 版本更新配置
static string g_latest_md5;  // 最新版本MD5
static string g_download_url;  // 下载地址
static const size_t CONFIG_THREAD_STACK_SIZE = 1 * 1024 * 1024;  // 1MB

// 简单的JSON字符串提取函数
string extract_json_string(const string& json, const string& key) {
    string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == string::npos) return "";

    pos = json.find(":", pos);
    if (pos == string::npos) return "";

    pos = json.find("\"", pos);
    if (pos == string::npos) return "";

    size_t end = json.find("\"", pos + 1);
    if (end == string::npos) return "";

    return json.substr(pos + 1, end - pos - 1);
}

// 简单的JSON数字提取函数
int extract_json_int(const string& json, const string& key) {
    string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == string::npos) return 0;

    pos = json.find(":", pos);
    if (pos == string::npos) return 0;

    // 跳过空格
    while (pos < json.length() && (json[pos] == ':' || json[pos] == ' ' || json[pos] == '\t')) {
        pos++;
    }

    return atoi(json.c_str() + pos);
}

string trim_copy(const string& value) {
    size_t start = 0;
    while (start < value.size() && isspace(static_cast<unsigned char>(value[start]))) {
        start++;
    }

    size_t end = value.size();
    while (end > start && isspace(static_cast<unsigned char>(value[end - 1]))) {
        end--;
    }

    return value.substr(start, end - start);
}

vector<string> split_command(const string& command) {
    vector<string> parts;
    string current;

    for (size_t i = 0; i < command.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(command[i]);
        if (isspace(ch)) {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
            continue;
        }
        current.push_back((char)ch);
    }

    if (!current.empty()) {
        parts.push_back(current);
    }

    return parts;
}

string json_escape(const string& input) {
    string escaped;
    escaped.reserve(input.size() + 8);

    for (size_t i = 0; i < input.size(); ++i) {
        switch (input[i]) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped.push_back(input[i]);
            break;
        }
    }

    return escaped;
}

static string build_default_virtual_subnet(int tunnel_port) {
    unsigned int octet2 = (unsigned int)((tunnel_port >> 8) & 0xFF);
    unsigned int octet3 = (unsigned int)(tunnel_port & 0xFF);

    if (octet2 == 0) {
        octet2 = 1;
    }

    stringstream subnet;
    subnet << "10." << octet2 << "." << octet3 << ".0/24";
    return subnet.str();
}

string canonical_server_key(const ServerConfig& server) {
    return to_string(server.id);
}

const ServerConfig* find_server_by_key_locked(const string& server_key) {
    for (size_t i = 0; i < g_servers.size(); ++i) {
        const ServerConfig& server = g_servers[i];
        if (server_key == server.name ||
            server_key == to_string(server.id) ||
            server_key == to_string(server.tunnel_port)) {
            return &server;
        }
    }
    return NULL;
}

ip_tunnel::StatusCode status_from_error(const string& error) {
    if (error == "server pool not found") {
        return ip_tunnel::kStatusServerNotFound;
    }
    if (error == "ip pool exhausted") {
        return ip_tunnel::kStatusPoolExhausted;
    }
    if (error == "lease not found") {
        return ip_tunnel::kStatusLeaseNotFound;
    }
    return ip_tunnel::kStatusInvalidRequest;
}

string make_status_json(ip_tunnel::StatusCode status,
                        const string& message,
                        const string& server_key = "") {
    stringstream json;
    json << "{"
         << "\"status\":" << (int)status << ","
         << "\"message\":\"" << json_escape(message) << "\"";

    if (!server_key.empty()) {
        json << ",\"server_key\":\"" << json_escape(server_key) << "\"";
    }

    json << "}";
    return json.str();
}

string generate_lease_json(const ServerConfig& server,
                           const IPPoolManager::LeaseRecord& lease,
                           const string& message) {
    stringstream json;
    json << "{"
         << "\"status\":" << (int)ip_tunnel::kStatusOk << ","
         << "\"message\":\"" << json_escape(message) << "\","
         << "\"server_key\":\"" << json_escape(canonical_server_key(server)) << "\","
         << "\"virtual_ip\":\"" << json_escape(lease.virtual_ip) << "\","
         << "\"subnet_mask\":\"" << json_escape(lease.subnet_mask) << "\","
         << "\"gateway_ip\":\"" << json_escape(lease.gateway_ip) << "\","
         << "\"mtu\":" << (int)ip_tunnel::kDefaultMtu << ","
         << "\"lease_seconds\":" << lease.lease_seconds << ","
         << "\"reused_previous_ip\":" << (lease.reused_previous_ip ? "true" : "false") << ","
         << "\"routes\":[\""
         << json_escape(server.game_server_ip + "/32")
         << "\"]}";
    return json.str();
}

bool rebuild_ip_pools(const vector<ServerConfig>& servers,
                      IPPoolManager* out_manager,
                      string* error) {
    if (!out_manager) {
        if (error) *error = "out_manager is null";
        return false;
    }

    IPPoolManager manager;
    for (size_t i = 0; i < servers.size(); ++i) {
        const ServerConfig& server = servers[i];

        IPPoolManager::PoolConfig pool_config;
        pool_config.server_key = canonical_server_key(server);
        pool_config.cidr = server.virtual_subnet;
        pool_config.gateway_ip = server.virtual_gateway;
        pool_config.lease_seconds = server.lease_seconds > 0
            ? (uint32_t)server.lease_seconds
            : ip_tunnel::kDefaultLeaseSeconds;

        string pool_error;
        if (!manager.ConfigurePool(pool_config, &pool_error)) {
            if (error) {
                *error = "server [" + server.name + "] pool config failed: " + pool_error;
            }
            return false;
        }
    }

    *out_manager = manager;
    return true;
}

// 从config.json读取版本更新配置
void load_version_config(const string& content) {
    // 查找version字段
    size_t version_pos = content.find("\"version\"");
    if (version_pos == string::npos) {
        printf("配置文件中没有version字段，跳过版本配置\n");
        return;
    }

    // 查找version对象开始
    size_t obj_start = content.find("{", version_pos);
    if (obj_start == string::npos) {
        printf("version字段格式错误\n");
        return;
    }

    size_t obj_end = content.find("}", obj_start);
    if (obj_end == string::npos) {
        printf("version对象未闭合\n");
        return;
    }

    string version_obj = content.substr(obj_start, obj_end - obj_start + 1);

    // 提取md5和download_url
    string md5 = extract_json_string(version_obj, "md5");
    string url = extract_json_string(version_obj, "download_url");

    if (!md5.empty() && !url.empty()) {
        g_latest_md5 = md5;
        g_download_url = url;
        printf("版本配置加载成功:\n");
        printf("  MD5: %s\n", g_latest_md5.c_str());
        printf("  下载地址: %s\n", g_download_url.c_str());
    } else {
        printf("version字段缺少md5或download_url\n");
    }
}

// 从config.json读取服务器配置
bool load_server_config(const char* config_file, const char* tunnel_server_ip) {
    printf("加载配置文件: %s\n", config_file);

    ifstream f(config_file);
    if (!f.is_open()) {
        fprintf(stderr, "无法打开配置文件: %s\n", config_file);
        return false;
    }

    // 读取文件内容
    stringstream buffer;
    buffer << f.rdbuf();
    string content = buffer.str();
    f.close();

    printf("配置文件大小: %zu 字节\n", content.size());

    // 加载版本更新配置
    load_version_config(content);

    // 临时存储，避免在解析过程中持有锁
    vector<ServerConfig> temp_servers;
    int id = 1;

    // 查找servers数组
    size_t servers_pos = content.find("\"servers\"");
    if (servers_pos == string::npos) {
        fprintf(stderr, "配置文件缺少servers字段\n");
        return false;
    }
    printf("找到servers字段位置: %zu\n", servers_pos);

    // 查找数组开始 [
    size_t array_start = content.find("[", servers_pos);
    if (array_start == string::npos) {
        fprintf(stderr, "配置文件格式错误: 找不到servers数组\n");
        return false;
    }
    printf("数组开始位置: %zu\n", array_start);

    // 查找数组结束 ]
    size_t array_end = content.find("]", array_start);
    if (array_end == string::npos || array_end <= array_start) {
        fprintf(stderr, "配置文件格式错误: servers数组未闭合\n");
        return false;
    }
    printf("数组结束位置: %zu\n", array_end);

    // 安全检查: 确保不会溢出
    if (array_end <= array_start + 1) {
        // 空数组
        fprintf(stderr, "配置文件格式错误: servers数组为空\n");
        return false;
    }

    // 提取数组内容
    size_t content_len = array_end - array_start - 1;
    if (content_len == 0 || content_len > 1000000) {
        fprintf(stderr, "配置文件格式错误: servers数组长度异常 (%zu)\n", content_len);
        return false;
    }

    printf("准备提取数组内容，长度: %zu\n", content_len);

    string array_content;
    try {
        array_content = content.substr(array_start + 1, content_len);
        printf("数组内容提取成功，实际长度: %zu\n", array_content.size());
    } catch (const exception& e) {
        fprintf(stderr, "提取数组内容失败: %s\n", e.what());
        return false;
    }

    // 按对象数量预估容量，避免大配置时频繁realloc；不是数量上限
    size_t estimated_servers = 0;
    for (char c : array_content) {
        if (c == '{') estimated_servers++;
    }
    if (estimated_servers > 0) {
        temp_servers.reserve(estimated_servers);
    }
    printf("temp_servers预分配完成，容量: %zu\n", temp_servers.capacity());

    // 逐个提取服务器对象 {...}
    size_t pos = 0;
    int server_count = 0;
    while (true) {
        size_t obj_start = array_content.find("{", pos);
        if (obj_start == string::npos) {
            printf("没有找到更多服务器对象\n");
            break;
        }

        size_t obj_end = array_content.find("}", obj_start);
        if (obj_end == string::npos) {
            printf("服务器对象未闭合\n");
            break;
        }

        printf("找到服务器对象 #%d: 位置 %zu - %zu\n", server_count + 1, obj_start, obj_end);

        // 安全检查
        if (obj_end <= obj_start || obj_end - obj_start > 10000) {
            fprintf(stderr, "服务器对象大小异常: %zu\n", obj_end - obj_start);
            break;
        }

        string obj;
        try {
            obj = array_content.substr(obj_start, obj_end - obj_start + 1);
            printf("对象内容长度: %zu\n", obj.size());
        } catch (const exception& e) {
            fprintf(stderr, "提取对象失败: %s\n", e.what());
            break;
        }

        // 使用C风格字符串暂存
        string name_str = extract_json_string(obj, "name");
        printf("  name: %s (长度: %zu)\n", name_str.c_str(), name_str.length());

        string game_ip_str = extract_json_string(obj, "game_server_ip");
        printf("  game_ip: %s (长度: %zu)\n", game_ip_str.c_str(), game_ip_str.length());

        string tunnel_ip_str = extract_json_string(obj, "tunnel_server_ip");
        if (tunnel_ip_str.empty()) {
            tunnel_ip_str.assign(tunnel_server_ip);
        }
        printf("  tunnel_ip: %s (长度: %zu)\n", tunnel_ip_str.c_str(), tunnel_ip_str.length());

        int port = extract_json_int(obj, "listen_port");
        printf("  port: %d\n", port);

        string download_url_str = extract_json_string(obj, "download_url");
        printf("  download_url: %s (长度: %zu)\n", download_url_str.c_str(), download_url_str.length());

        string virtual_subnet_str = extract_json_string(obj, "virtual_subnet");
        if (virtual_subnet_str.empty()) {
            virtual_subnet_str = build_default_virtual_subnet(port);
        }
        printf("  virtual_subnet: %s\n", virtual_subnet_str.c_str());

        string virtual_gateway_str = extract_json_string(obj, "virtual_gateway");
        printf("  virtual_gateway: %s\n", virtual_gateway_str.c_str());

        int lease_seconds = extract_json_int(obj, "lease_seconds");
        if (lease_seconds <= 0) {
            lease_seconds = (int)ip_tunnel::kDefaultLeaseSeconds;
        }
        printf("  lease_seconds: %d\n", lease_seconds);

        // 使用emplace_back避免拷贝
        printf("准备添加到临时列表...\n");
        try {
            ServerConfig s;
            s.id = id++;
            s.name.assign(name_str.c_str(), name_str.length());
            s.game_server_ip.assign(game_ip_str.c_str(), game_ip_str.length());
            s.tunnel_server_ip.assign(tunnel_ip_str.c_str(), tunnel_ip_str.length());
            s.tunnel_port = port;
            s.download_url.assign(download_url_str.c_str(), download_url_str.length());
            s.virtual_subnet.assign(virtual_subnet_str.c_str(), virtual_subnet_str.length());
            s.virtual_gateway.assign(virtual_gateway_str.c_str(), virtual_gateway_str.length());
            s.lease_seconds = lease_seconds;

            printf("ServerConfig构造完成，准备push_back...\n");
            temp_servers.push_back(s);
            printf("✓ 服务器 #%d 添加成功\n", s.id);
            server_count++;
        } catch (const bad_alloc& e) {
            fprintf(stderr, "内存分配失败: %s\n", e.what());
            fprintf(stderr, "temp_servers当前大小: %zu, 容量: %zu\n",
                    temp_servers.size(), temp_servers.capacity());
            break;
        } catch (const exception& e) {
            fprintf(stderr, "添加服务器失败: %s\n", e.what());
            break;
        }

        pos = obj_end + 1;
        if (pos >= array_content.size()) {
            printf("已到达数组末尾\n");
            break;
        }
    }

    IPPoolManager temp_pool_manager;
    string pool_error;
    if (!rebuild_ip_pools(temp_servers, &temp_pool_manager, &pool_error)) {
        fprintf(stderr, "IP池配置失败: %s\n", pool_error.c_str());
        return false;
    }

    // 一次性更新全局列表（加锁）
    {
        lock_guard<mutex> lock(g_servers_mutex);
        g_servers = temp_servers;
        g_ip_pool_manager = temp_pool_manager;
    }

    printf("加载了 %zu 个服务器配置\n", g_servers.size());
    return g_servers.size() > 0;
}

// 生成服务器列表JSON响应
string generate_server_list_json() {
    stringstream json;
    json << "{\"servers\":[";

    {
        lock_guard<mutex> lock(g_servers_mutex);
        for (size_t i = 0; i < g_servers.size(); i++) {
            const ServerConfig& s = g_servers[i];

            if (i > 0) json << ",";

            json << "{"
                 << "\"id\":" << s.id << ","
                 << "\"name\":\"" << json_escape(s.name) << "\","
                 << "\"game_server_ip\":\"" << json_escape(s.game_server_ip) << "\","
                 << "\"tunnel_server_ip\":\"" << json_escape(s.tunnel_server_ip) << "\","
                 << "\"tunnel_port\":" << s.tunnel_port << ","
                 << "\"download_url\":\"" << json_escape(s.download_url) << "\","
                 << "\"virtual_subnet\":\"" << json_escape(s.virtual_subnet) << "\","
                 << "\"virtual_gateway\":\"" << json_escape(s.virtual_gateway) << "\","
                 << "\"lease_seconds\":" << s.lease_seconds
                 << "}";
        }
    }

    json << "]}";
    return json.str();
}

// 生成版本信息JSON响应
string generate_version_json() {
    stringstream json;
    json << "{"
         << "\"md5\":\"" << json_escape(g_latest_md5) << "\","
         << "\"download_url\":\"" << json_escape(g_download_url) << "\""
         << "}";
    return json.str();
}

// 处理TCP请求
void handle_tcp_request(int client_fd) {
    char buffer[1024];
    int n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buffer[n] = '\0';

    string request = trim_copy(string(buffer));
    vector<string> parts = split_command(request);

    printf("[TCP] 收到请求: %s\n", request.c_str());

    // 处理 GET_SERVERS 请求
    if (request == "GET_SERVERS") {
        string json_response = generate_server_list_json();
        send(client_fd, json_response.c_str(), json_response.length(), 0);
        printf("[TCP] 已发送服务器列表 (%zu 字节)\n", json_response.length());
    }
    // 处理 GET_VERSION 请求
    else if (request == "GET_VERSION") {
        if (g_latest_md5.empty() || g_download_url.empty()) {
            const char* error_msg = "{\"error\":\"Version not configured\"}";
            send(client_fd, error_msg, strlen(error_msg), 0);
            printf("[TCP] 版本配置未设置\n");
        } else {
            string json_response = generate_version_json();
            send(client_fd, json_response.c_str(), json_response.length(), 0);
            printf("[TCP] 已发送版本信息 (%zu 字节): MD5=%s\n",
                   json_response.length(), g_latest_md5.c_str());
        }
    }
    else if (!parts.empty() && parts[0] == "LEASE_IP") {
        if (parts.size() < 4) {
            string json_response = make_status_json(ip_tunnel::kStatusInvalidRequest,
                                                    "usage: LEASE_IP <server_key> <session_uuid> <client_id> [preferred_ip]");
            send(client_fd, json_response.c_str(), json_response.length(), 0);
        } else {
            string json_response;
            lock_guard<mutex> lock(g_servers_mutex);
            const ServerConfig* server = find_server_by_key_locked(parts[1]);
            if (server == NULL) {
                json_response = make_status_json(ip_tunnel::kStatusServerNotFound, "server not found", parts[1]);
            } else {
                ip_tunnel::LeaseRequest lease_request;
                lease_request.server_key = canonical_server_key(*server);
                lease_request.session_uuid = parts[2];
                lease_request.client_id = parts[3];
                if (parts.size() >= 5) {
                    lease_request.preferred_ip = parts[4];
                }

                IPPoolManager::LeaseRecord lease_record;
                string error;
                if (g_ip_pool_manager.AcquireLease(lease_request, &lease_record, &error)) {
                    json_response = generate_lease_json(*server, lease_record, "lease granted");
                } else {
                    json_response = make_status_json(status_from_error(error), error, canonical_server_key(*server));
                }
            }

            send(client_fd, json_response.c_str(), json_response.length(), 0);
        }
    }
    else if (!parts.empty() && parts[0] == "RENEW_LEASE") {
        if (parts.size() < 3) {
            string json_response = make_status_json(ip_tunnel::kStatusInvalidRequest,
                                                    "usage: RENEW_LEASE <server_key> <session_uuid>");
            send(client_fd, json_response.c_str(), json_response.length(), 0);
        } else {
            string json_response;
            lock_guard<mutex> lock(g_servers_mutex);
            const ServerConfig* server = find_server_by_key_locked(parts[1]);
            if (server == NULL) {
                json_response = make_status_json(ip_tunnel::kStatusServerNotFound, "server not found", parts[1]);
            } else {
                IPPoolManager::LeaseRecord lease_record;
                string error;
                if (g_ip_pool_manager.RenewLease(canonical_server_key(*server), parts[2], &lease_record, &error)) {
                    json_response = generate_lease_json(*server, lease_record, "lease renewed");
                } else {
                    json_response = make_status_json(status_from_error(error), error, canonical_server_key(*server));
                }
            }

            send(client_fd, json_response.c_str(), json_response.length(), 0);
        }
    }
    else if (!parts.empty() && parts[0] == "RELEASE_LEASE") {
        if (parts.size() < 3) {
            string json_response = make_status_json(ip_tunnel::kStatusInvalidRequest,
                                                    "usage: RELEASE_LEASE <server_key> <session_uuid>");
            send(client_fd, json_response.c_str(), json_response.length(), 0);
        } else {
            string json_response;
            lock_guard<mutex> lock(g_servers_mutex);
            const ServerConfig* server = find_server_by_key_locked(parts[1]);
            if (server == NULL) {
                json_response = make_status_json(ip_tunnel::kStatusServerNotFound, "server not found", parts[1]);
            } else if (g_ip_pool_manager.ReleaseLease(canonical_server_key(*server), parts[2])) {
                json_response = make_status_json(ip_tunnel::kStatusOk, "lease released", canonical_server_key(*server));
            } else {
                json_response = make_status_json(ip_tunnel::kStatusLeaseNotFound, "lease not found", canonical_server_key(*server));
            }

            send(client_fd, json_response.c_str(), json_response.length(), 0);
        }
    }
    else {
        // 未知请求
        const char* error_msg = "{\"error\":\"Unknown request\"}";
        send(client_fd, error_msg, strlen(error_msg), 0);
        printf("[TCP] 未知请求: %s\n", request.c_str());
    }

    close(client_fd);
}

void* tcp_server_thread(void* arg) {
    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket failed");
        return NULL;
    }

    // 设置端口复用
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 启用双栈模式，兼容IPv4和IPv6客户端
    int v6only = 0;
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(g_api_port);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(listen_fd);
        return NULL;
    }

    if (listen(listen_fd, 10) < 0) {
        perror("listen failed");
        close(listen_fd);
        return NULL;
    }

    printf("TCP配置服务器启动在端口 %d\n", g_api_port);
    printf("支持的命令:\n");
    printf("  - GET_SERVERS: 获取服务器列表\n");
    printf("  - GET_VERSION: 获取版本信息(MD5 + 下载地址)\n");
    printf("  - LEASE_IP <server_key> <session_uuid> <client_id> [preferred_ip]\n");
    printf("  - RENEW_LEASE <server_key> <session_uuid>\n");
    printf("  - RELEASE_LEASE <server_key> <session_uuid>\n");

    while (g_running) {
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept failed");
            break;
        }

        char client_ip[INET6_ADDRSTRLEN] = "unknown";
        int client_port = 0;
        if (client_addr.ss_family == AF_INET) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)&client_addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, sizeof(client_ip));
            client_port = ntohs(addr_in->sin_port);
        } else if (client_addr.ss_family == AF_INET6) {
            struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)&client_addr;
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, client_ip, sizeof(client_ip));
            client_port = ntohs(addr_in6->sin6_port);
        }

        printf("[TCP] 新连接来自 %s:%d\n", client_ip, client_port);

        // 直接处理请求（简单实现，不使用线程池）
        handle_tcp_request(client_fd);
    }

    close(listen_fd);
    printf("TCP配置服务器已停止\n");
    return NULL;
}

// 启动TCP配置服务器
pthread_t start_tcp_config_server(const char* config_file, const char* tunnel_server_ip, int api_port) {
    g_api_port = api_port;

    // 保存配置路径供热重载使用
    g_config_file = config_file;
    g_tunnel_server_ip = tunnel_server_ip;

    // 加载服务器配置
    if (!load_server_config(config_file, tunnel_server_ip)) {
        fprintf(stderr, "加载服务器配置失败\n");
        return 0;
    }

    // 创建TCP服务器线程（设置更大的栈空间）
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    // 减少线程栈占用，避免配置服务额外占用过多内存
    size_t stack_size = CONFIG_THREAD_STACK_SIZE;
    pthread_attr_setstacksize(&attr, stack_size);
    printf("设置线程栈大小: %zu MB\n", stack_size / (1024 * 1024));

    if (pthread_create(&tid, &attr, tcp_server_thread, NULL) != 0) {
        perror("pthread_create failed");
        pthread_attr_destroy(&attr);
        return 0;
    }

    pthread_attr_destroy(&attr);

    // 启动配置文件监控线程（自动热重载）
    if (pthread_create(&g_monitor_thread, NULL, config_monitor_thread, NULL) != 0) {
        perror("创建配置监控线程失败");
        printf("警告: 自动热重载功能不可用，但可以使用 kill -HUP 手动重载\n");
        g_monitor_thread = 0;
    } else {
        printf("配置文件自动监控已启动\n");
    }

    return tid;
}

// 停止TCP配置服务器
void stop_tcp_config_server() {
    g_running = false;
    g_auto_reload = false;  // 停止配置监控

    // 等待监控线程退出
    if (g_monitor_thread != 0) {
        printf("正在停止配置文件监控...\n");
        pthread_join(g_monitor_thread, NULL);
        g_monitor_thread = 0;
        printf("配置文件监控已停止\n");
    }
}

// 重新加载配置
bool reload_tcp_config() {
    printf("\n========================================\n");
    printf("收到重载配置信号\n");
    printf("========================================\n");

    if (g_config_file.empty() || g_tunnel_server_ip.empty()) {
        fprintf(stderr, "配置文件路径未初始化\n");
        return false;
    }

    printf("重新加载配置文件: %s\n", g_config_file.c_str());

    if (load_server_config(g_config_file.c_str(), g_tunnel_server_ip.c_str())) {
        printf("✓ 配置重载成功，当前服务器数量: %zu\n", g_servers.size());

        // 打印服务器列表
        lock_guard<mutex> lock(g_servers_mutex);
        printf("\n当前服务器列表:\n");
        printf("------------------------------------\n");
        for (const auto& s : g_servers) {
            printf("  [%d] %s\n", s.id, s.name.c_str());
            printf("      游戏服务器: %s\n", s.game_server_ip.c_str());
            printf("      隧道端口: %d\n", s.tunnel_port);
        }
        printf("------------------------------------\n\n");

        return true;
    } else {
        fprintf(stderr, "✗ 配置重载失败\n");
        return false;
    }
}

// 配置文件监控线程
void* config_monitor_thread(void* arg) {
    printf("配置文件自动重载监控已启动\n");
    printf("监控文件: %s\n", g_config_file.c_str());

    // 创建inotify实例
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init failed");
        return NULL;
    }

    // 监控配置文件的修改和移动事件
    int watch_fd = inotify_add_watch(inotify_fd, g_config_file.c_str(),
                                     IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO);
    if (watch_fd < 0) {
        perror("inotify_add_watch failed");
        close(inotify_fd);
        return NULL;
    }

    char buffer[4096];
    time_t last_reload = 0;

    while (g_running && g_auto_reload) {
        // 使用select设置超时，避免阻塞在read上
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(inotify_fd, &fds);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ret = select(inotify_fd + 1, &fds, NULL, NULL, &timeout);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("select failed");
            break;
        }

        if (ret == 0) {
            // 超时，继续循环检查g_running
            continue;
        }

        // 读取inotify事件
        ssize_t len = read(inotify_fd, buffer, sizeof(buffer));
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("read inotify failed");
            break;
        }

        // 处理事件
        for (char* ptr = buffer; ptr < buffer + len; ) {
            struct inotify_event* event = (struct inotify_event*)ptr;

            if (event->mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO)) {
                // 防止短时间内多次重载（去抖动）
                time_t now = time(NULL);
                if (now - last_reload >= 2) {  // 至少间隔2秒
                    printf("\n[自动重载] 检测到配置文件变化\n");

                    // 稍微延迟，确保文件写入完成
                    usleep(100000);  // 100ms

                    reload_tcp_config();
                    last_reload = now;
                }
            }

            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    // 清理
    inotify_rm_watch(inotify_fd, watch_fd);
    close(inotify_fd);

    printf("配置文件监控已停止\n");
    return NULL;
}
