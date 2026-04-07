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
#include <cstdarg>
#include <sys/inotify.h>
#include <sys/select.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "ip_pool_manager.h"

using namespace std;

class Logger {
public:
    static void warning(const string& msg);
    static void error(const string& msg);
    static void debug(const string& msg);
};

// 前向声明
void* config_monitor_thread(void* arg);

// 节点配置结构
struct NodeConfig {
    int id;
    string name;
    string server_virtual_ip;
    bool bind_on_gateway;
    string download_url;  // 客户端下载地址

    NodeConfig()
        : id(0), bind_on_gateway(false) {}
};

struct NetworkConfig {
    int tunnel_port;
    string virtual_subnet;
    string virtual_gateway;
    string tunnel_server_ip;
    int max_connections;
    int lease_seconds;

    NetworkConfig()
        : tunnel_port(33223),
          max_connections(100),
          lease_seconds((int)ip_tunnel::kDefaultLeaseSeconds) {}
};

// 全局变量
static vector<NodeConfig> g_nodes;
static NetworkConfig g_network;
static mutex g_servers_mutex;  // 保护节点列表、网络配置和IP池
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

static bool tcp_config_trace_enabled() {
    static int cached = -1;
    if (cached == -1) {
        const char* env = getenv("DNF_TCP_CONFIG_DEBUG");
        cached = (env != NULL && env[0] != '\0' && strcmp(env, "0") != 0) ? 1 : 0;
    }
    return cached == 1;
}

static void tcp_config_tracef(const char* fmt, ...) {
    if (!tcp_config_trace_enabled()) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

static string tcp_config_errno_text(int err) {
    return string(strerror(err));
}

static void tcp_config_log_warn(const string& msg) {
    Logger::warning("[TCP配置] " + msg);
}

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

static string strip_json_comments(const string& content) {
    string result;
    result.reserve(content.size());

    bool in_string = false;
    bool escape = false;

    for (size_t i = 0; i < content.size(); ++i) {
        char ch = content[i];

        if (escape) {
            result += ch;
            escape = false;
            continue;
        }

        if (ch == '\\') {
            result += ch;
            if (in_string) {
                escape = true;
            }
            continue;
        }

        if (ch == '"') {
            result += ch;
            in_string = !in_string;
            continue;
        }

        if (!in_string) {
            if (ch == '#') {
                while (i < content.size() && content[i] != '\n') {
                    ++i;
                }
                if (i < content.size() && content[i] == '\n') {
                    result += '\n';
                }
                continue;
            }

            if (ch == '/' && i + 1 < content.size() && content[i + 1] == '/') {
                i += 2;
                while (i < content.size() && content[i] != '\n') {
                    ++i;
                }
                if (i < content.size() && content[i] == '\n') {
                    result += '\n';
                }
                continue;
            }
        }

        result += ch;
    }

    return result;
}

bool extract_json_bool(const string& json, const string& key, bool* found = NULL) {
    string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == string::npos) {
        if (found != NULL) {
            *found = false;
        }
        return false;
    }

    pos = json.find(":", pos);
    if (pos == string::npos) {
        if (found != NULL) {
            *found = false;
        }
        return false;
    }

    while (pos < json.length() &&
           (json[pos] == ':' || json[pos] == ' ' || json[pos] == '\t' ||
            json[pos] == '\r' || json[pos] == '\n')) {
        pos++;
    }

    if (found != NULL) {
        *found = true;
    }

    return json.compare(pos, 4, "true") == 0 || json.compare(pos, 1, "1") == 0;
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

static string build_auto_virtual_gateway(const string& subnet_cidr, int tunnel_port) {
    size_t slash = subnet_cidr.find('/');
    string base_ip = (slash == string::npos) ? subnet_cidr : subnet_cidr.substr(0, slash);
    int prefix_bits = 24;
    if (slash != string::npos) {
        prefix_bits = atoi(subnet_cidr.c_str() + slash + 1);
    }

    if (prefix_bits < 0 || prefix_bits > 30) {
        prefix_bits = 24;
    }

    in_addr network_addr{};
    if (inet_pton(AF_INET, base_ip.c_str(), &network_addr) != 1) {
        return "";
    }

    uint32_t network_host = ntohl(network_addr.s_addr);
    uint32_t host_count = 1u << (32 - prefix_bits);
    if (host_count <= 2) {
        return "";
    }

    (void)tunnel_port;
    uint32_t gateway_host = network_host + 1;

    in_addr gateway_addr{};
    gateway_addr.s_addr = htonl(gateway_host);

    char gateway_str[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &gateway_addr, gateway_str, sizeof(gateway_str))) {
        return "";
    }
    return string(gateway_str);
}

static string build_virtual_ip_with_offset(const string& subnet_cidr, uint32_t host_offset) {
    size_t slash = subnet_cidr.find('/');
    string base_ip = (slash == string::npos) ? subnet_cidr : subnet_cidr.substr(0, slash);
    int prefix_bits = 24;
    if (slash != string::npos) {
        prefix_bits = atoi(subnet_cidr.c_str() + slash + 1);
    }

    if (prefix_bits < 0 || prefix_bits > 30) {
        prefix_bits = 24;
    }

    in_addr network_addr{};
    if (inet_pton(AF_INET, base_ip.c_str(), &network_addr) != 1) {
        return "";
    }

    uint32_t network_host = ntohl(network_addr.s_addr);
    uint32_t host_count = 1u << (32 - prefix_bits);
    if (host_offset >= host_count - 1) {
        return "";
    }

    uint32_t ip_host = network_host + host_offset;
    in_addr ip_addr{};
    ip_addr.s_addr = htonl(ip_host);

    char ip_str[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str))) {
        return "";
    }
    return string(ip_str);
}

string canonical_node_key(const NodeConfig& node) {
    return to_string(node.id);
}

const NodeConfig* find_node_by_key_locked(const string& node_key) {
    for (size_t i = 0; i < g_nodes.size(); ++i) {
        const NodeConfig& node = g_nodes[i];
        if (node_key == node.name ||
            node_key == to_string(node.id) ||
            node_key == node.server_virtual_ip) {
            return &node;
        }
    }
    return NULL;
}

size_t find_matching_brace(const string& content, size_t open_pos, char open_ch, char close_ch) {
    int depth = 0;
    bool in_string = false;
    bool escape = false;

    for (size_t i = open_pos; i < content.size(); ++i) {
        char ch = content[i];
        if (in_string) {
            if (escape) {
                escape = false;
            } else if (ch == '\\') {
                escape = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }

        if (ch == '"') {
            in_string = true;
            continue;
        }
        if (ch == open_ch) {
            depth++;
        } else if (ch == close_ch) {
            depth--;
            if (depth == 0) {
                return i;
            }
        }
    }

    return string::npos;
}

string extract_json_object(const string& json, const string& key) {
    string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == string::npos) return "";

    size_t start = json.find("{", pos);
    if (start == string::npos) return "";

    size_t end = find_matching_brace(json, start, '{', '}');
    if (end == string::npos || end < start) return "";

    return json.substr(start, end - start + 1);
}

vector<string> extract_json_object_array(const string& json, const string& key) {
    vector<string> objects;
    string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == string::npos) return objects;

    size_t array_start = json.find("[", pos);
    if (array_start == string::npos) return objects;

    size_t array_end = find_matching_brace(json, array_start, '[', ']');
    if (array_end == string::npos || array_end <= array_start) return objects;

    size_t cursor = array_start + 1;
    while (cursor < array_end) {
        size_t obj_start = json.find("{", cursor);
        if (obj_start == string::npos || obj_start >= array_end) break;
        size_t obj_end = find_matching_brace(json, obj_start, '{', '}');
        if (obj_end == string::npos || obj_end > array_end) break;
        objects.push_back(json.substr(obj_start, obj_end - obj_start + 1));
        cursor = obj_end + 1;
    }

    return objects;
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

string generate_lease_json(const NodeConfig& node,
                           const IPPoolManager::LeaseRecord& lease,
                           const string& message) {
    stringstream json;
    json << "{"
         << "\"status\":" << (int)ip_tunnel::kStatusOk << ","
         << "\"message\":\"" << json_escape(message) << "\","
         << "\"server_key\":\"" << json_escape(canonical_node_key(node)) << "\","
         << "\"virtual_ip\":\"" << json_escape(lease.virtual_ip) << "\","
         << "\"subnet_mask\":\"" << json_escape(lease.subnet_mask) << "\","
         << "\"gateway_ip\":\"" << json_escape(lease.gateway_ip) << "\","
         << "\"server_virtual_ip\":\"" << json_escape(lease.server_virtual_ip) << "\","
         << "\"mtu\":" << (int)ip_tunnel::kDefaultMtu << ","
         << "\"lease_seconds\":" << lease.lease_seconds << ","
         << "\"reused_previous_ip\":" << (lease.reused_previous_ip ? "true" : "false") << ","
         << "\"routes\":[";

    if (!g_network.virtual_subnet.empty()) {
        json << "\"" << json_escape(g_network.virtual_subnet) << "\"";
    }

    json << "]}";
    return json.str();
}

bool rebuild_ip_pools(const NetworkConfig& network,
                      const vector<NodeConfig>& nodes,
                      IPPoolManager* out_manager,
                      string* error) {
    if (!out_manager) {
        if (error) *error = "out_manager is null";
        return false;
    }

    IPPoolManager manager;
    for (size_t i = 0; i < nodes.size(); ++i) {
        IPPoolManager::PoolConfig pool_config;
        pool_config.pool_key = canonical_node_key(nodes[i]);
        pool_config.cidr = network.virtual_subnet;
        pool_config.gateway_ip = network.virtual_gateway;
        pool_config.lease_seconds = network.lease_seconds > 0
            ? (uint32_t)network.lease_seconds
            : ip_tunnel::kDefaultLeaseSeconds;

        if (!nodes[i].server_virtual_ip.empty()) {
            pool_config.additional_reserved_ips.push_back(nodes[i].server_virtual_ip);
        }

        string pool_error;
        if (!manager.ConfigurePool(pool_config, &pool_error)) {
            if (error) {
                *error = "pool[" + pool_config.pool_key + "] config failed: " + pool_error;
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

// 从config.json读取节点和网络配置（仅支持 network + nodes 新格式）
bool load_server_config(const char* config_file, const char* tunnel_server_ip) {
    printf("加载配置文件: %s\n", config_file);

    ifstream f(config_file);
    if (!f.is_open()) {
        fprintf(stderr, "无法打开配置文件: %s\n", config_file);
        return false;
    }

    stringstream buffer;
    buffer << f.rdbuf();
    string content = strip_json_comments(buffer.str());
    f.close();

    printf("配置文件大小: %zu 字节\n", content.size());

    load_version_config(content);

    NetworkConfig temp_network;
    temp_network.tunnel_server_ip = tunnel_server_ip ? tunnel_server_ip : "";
    vector<NodeConfig> temp_nodes;

    string network_obj = extract_json_object(content, "network");
    if (network_obj.empty()) {
        fprintf(stderr, "配置文件缺少network对象\n");
        return false;
    }

    temp_network.tunnel_port = extract_json_int(network_obj, "tunnel_port");
    if (temp_network.tunnel_port <= 0) {
        fprintf(stderr, "network.tunnel_port 无效\n");
        return false;
    }

    temp_network.virtual_subnet = extract_json_string(network_obj, "virtual_subnet");
    if (temp_network.virtual_subnet.empty()) {
        temp_network.virtual_subnet = build_default_virtual_subnet(temp_network.tunnel_port);
    }

    temp_network.virtual_gateway = extract_json_string(network_obj, "virtual_gateway");
    if (temp_network.virtual_gateway.empty()) {
        temp_network.virtual_gateway =
            build_auto_virtual_gateway(temp_network.virtual_subnet, temp_network.tunnel_port);
    }

    string network_tunnel_ip = extract_json_string(network_obj, "tunnel_server_ip");
    if (!network_tunnel_ip.empty()) {
        temp_network.tunnel_server_ip = network_tunnel_ip;
    }

    int network_max_connections = extract_json_int(network_obj, "max_connections");
    if (network_max_connections > 0) {
        temp_network.max_connections = network_max_connections;
    }

    int network_lease_seconds = extract_json_int(network_obj, "lease_seconds");
    if (network_lease_seconds > 0) {
        temp_network.lease_seconds = network_lease_seconds;
    }

    string api_obj = extract_json_object(content, "api_config");
    if (!api_obj.empty()) {
        int api_port = extract_json_int(api_obj, "port");
        if (api_port > 0) {
            g_api_port = api_port;
        }
    }

    vector<string> node_objects = extract_json_object_array(content, "nodes");
    if (node_objects.empty()) {
        fprintf(stderr, "配置文件缺少nodes数组或nodes为空\n");
        return false;
    }

    bool has_explicit_gateway_binding = false;
    bool has_any_bind_flag = false;
    temp_nodes.reserve(node_objects.size());
    for (size_t i = 0; i < node_objects.size(); ++i) {
        NodeConfig node;
        node.id = (int)i + 1;
        node.name = extract_json_string(node_objects[i], "name");
        if (node.name.empty()) {
            node.name = "节点" + to_string(node.id);
        }
        node.server_virtual_ip = extract_json_string(node_objects[i], "server_virtual_ip");
        if (node.server_virtual_ip.empty()) {
            node.server_virtual_ip = build_virtual_ip_with_offset(temp_network.virtual_subnet, (uint32_t)(i + 2));
        }
        node.download_url = extract_json_string(node_objects[i], "download_url");
        bool bind_found = false;
        node.bind_on_gateway = extract_json_bool(node_objects[i], "bind_on_gateway", &bind_found);
        if (bind_found) {
            has_any_bind_flag = true;
        }
        if (node.bind_on_gateway) {
            has_explicit_gateway_binding = true;
        }

        printf("节点 #%d: name=%s server_virtual_ip=%s\n",
               node.id,
               node.name.c_str(),
               node.server_virtual_ip.c_str());

        if (node.server_virtual_ip.empty()) {
            fprintf(stderr, "节点 %s 缺少有效的server_virtual_ip\n", node.name.c_str());
            return false;
        }
        temp_nodes.push_back(node);
    }

    if (!has_explicit_gateway_binding && !has_any_bind_flag && temp_nodes.size() == 1) {
        temp_nodes[0].bind_on_gateway = true;
    }

    IPPoolManager temp_pool_manager;
    string pool_error;
    if (!rebuild_ip_pools(temp_network, temp_nodes, &temp_pool_manager, &pool_error)) {
        fprintf(stderr, "IP池配置失败: %s\n", pool_error.c_str());
        return false;
    }

    {
        lock_guard<mutex> lock(g_servers_mutex);
        g_network = temp_network;
        g_nodes.swap(temp_nodes);
        g_ip_pool_manager = temp_pool_manager;
    }

    printf("加载了 %zu 个节点配置\n", g_nodes.size());
    return !g_nodes.empty();
}

// 生成服务器列表JSON响应
string generate_server_list_json() {
    stringstream json;
    json << "{\"servers\":[";

    {
        lock_guard<mutex> lock(g_servers_mutex);
        for (size_t i = 0; i < g_nodes.size(); i++) {
            const NodeConfig& s = g_nodes[i];

            if (i > 0) json << ",";

            json << "{"
                 << "\"id\":" << s.id << ","
                 << "\"name\":\"" << json_escape(s.name) << "\","
                 << "\"server_virtual_ip\":\"" << json_escape(s.server_virtual_ip) << "\","
                 << "\"tunnel_server_ip\":\"" << json_escape(g_network.tunnel_server_ip) << "\","
                 << "\"tunnel_port\":" << g_network.tunnel_port << ","
                 << "\"download_url\":\"" << json_escape(s.download_url) << "\","
                 << "\"virtual_subnet\":\"" << json_escape(g_network.virtual_subnet) << "\","
                 << "\"virtual_gateway\":\"" << json_escape(g_network.virtual_gateway) << "\","
                 << "\"lease_seconds\":" << g_network.lease_seconds << ","
                 << "\"bind_on_gateway\":" << (s.bind_on_gateway ? "true" : "false")
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

static void send_tcp_response(int client_fd, const string& response, const char* context, const char* request = NULL) {
    ssize_t sent = send(client_fd, response.c_str(), response.length(), 0);
    if (sent < 0) {
        fprintf(stderr, "[TCP][WARN] send failed context=%s errno=%d request=%s\n",
                context, errno, request != NULL ? request : "(unknown)");
        tcp_config_log_warn("发送响应失败: context=" + string(context) +
                            " errno=" + to_string(errno) +
                            " error=" + tcp_config_errno_text(errno) +
                            " request=" + string(request != NULL ? request : "(unknown)"));
    }
}

// 处理TCP请求
void handle_tcp_request(int client_fd, const string& client_label) {
    char buffer[1024];
    int n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0) {
        if (n == 0) {
            fprintf(stderr, "[TCP][WARN] connection closed before request: client=%s\n",
                    client_label.c_str());
            tcp_config_log_warn("连接在读取请求前被关闭: client=" + client_label);
        } else {
            fprintf(stderr, "[TCP][WARN] recv request failed: client=%s errno=%d\n",
                    client_label.c_str(), errno);
            tcp_config_log_warn("读取请求失败: client=" + client_label +
                                " errno=" + to_string(errno) +
                                " error=" + tcp_config_errno_text(errno));
        }
        close(client_fd);
        return;
    }
    buffer[n] = '\0';

    string request = trim_copy(string(buffer));
    vector<string> parts = split_command(request);

    tcp_config_tracef("[TCP] 收到请求: %s\n", request.c_str());

    // 处理 GET_SERVERS 请求
    if (request == "GET_SERVERS") {
        string json_response = generate_server_list_json();
        send_tcp_response(client_fd, json_response, "GET_SERVERS", request.c_str());
        tcp_config_tracef("[TCP] 已发送服务器列表 (%zu 字节)\n", json_response.length());
    }
    // 处理 GET_VERSION 请求
    else if (request == "GET_VERSION") {
        string json_response = generate_version_json();
        send_tcp_response(client_fd, json_response, "GET_VERSION", request.c_str());
        if (g_latest_md5.empty() || g_download_url.empty()) {
            tcp_config_tracef("[TCP] 版本配置未设置，已发送空版本信息 (%zu 字节)\n", json_response.length());
        } else {
            tcp_config_tracef("[TCP] 已发送版本信息 (%zu 字节): MD5=%s\n",
                   json_response.length(), g_latest_md5.c_str());
        }
    }
    else if (!parts.empty() && parts[0] == "LEASE_IP") {
        if (parts.size() < 4) {
            string json_response = make_status_json(ip_tunnel::kStatusInvalidRequest,
                                                    "usage: LEASE_IP <server_key> <session_uuid> <client_id> [preferred_ip]");
            send_tcp_response(client_fd, json_response, "LEASE_IP/usage", request.c_str());
        } else {
            string json_response;
            lock_guard<mutex> lock(g_servers_mutex);
            const NodeConfig* node = find_node_by_key_locked(parts[1]);
            if (node == NULL) {
                json_response = make_status_json(ip_tunnel::kStatusServerNotFound, "node not found", parts[1]);
            } else {
                ip_tunnel::LeaseRequest lease_request;
                lease_request.server_key = canonical_node_key(*node);
                lease_request.session_uuid = parts[2];
                lease_request.client_id = parts[3];
                if (parts.size() >= 5) {
                    lease_request.preferred_ip = parts[4];
                }

                IPPoolManager::LeaseRecord lease_record;
                string error;
                if (g_ip_pool_manager.AcquireLease(canonical_node_key(*node), lease_request, &lease_record, &error)) {
                    lease_record.server_virtual_ip = node->server_virtual_ip;
                    Logger::debug("[TCP閰嶇疆] lease granted: client=" + client_label +
                                  " server_key=" + canonical_node_key(*node) +
                                  " virtual_ip=" + lease_record.virtual_ip +
                                  " gateway=" + lease_record.gateway_ip +
                                  " server_virtual_ip=" + lease_record.server_virtual_ip +
                                  " route=" + g_network.virtual_subnet);
                    json_response = generate_lease_json(*node, lease_record, "lease granted");
                } else {
                    json_response = make_status_json(status_from_error(error), error, canonical_node_key(*node));
                }
            }

            send_tcp_response(client_fd, json_response, "LEASE_IP", request.c_str());
        }
    }
    else if (!parts.empty() && parts[0] == "RENEW_LEASE") {
        if (parts.size() < 3) {
            string json_response = make_status_json(ip_tunnel::kStatusInvalidRequest,
                                                    "usage: RENEW_LEASE <server_key> <session_uuid>");
            send_tcp_response(client_fd, json_response, "RENEW_LEASE/usage", request.c_str());
        } else {
            string json_response;
            lock_guard<mutex> lock(g_servers_mutex);
            const NodeConfig* node = find_node_by_key_locked(parts[1]);
            if (node == NULL) {
                json_response = make_status_json(ip_tunnel::kStatusServerNotFound, "node not found", parts[1]);
            } else {
                IPPoolManager::LeaseRecord lease_record;
                string error;
                if (g_ip_pool_manager.RenewLease(canonical_node_key(*node), parts[2], &lease_record, &error)) {
                    lease_record.server_virtual_ip = node->server_virtual_ip;
                    Logger::debug("[TCP閰嶇疆] lease renewed: client=" + client_label +
                                  " server_key=" + canonical_node_key(*node) +
                                  " virtual_ip=" + lease_record.virtual_ip +
                                  " gateway=" + lease_record.gateway_ip +
                                  " server_virtual_ip=" + lease_record.server_virtual_ip +
                                  " route=" + g_network.virtual_subnet);
                    json_response = generate_lease_json(*node, lease_record, "lease renewed");
                } else {
                    fprintf(stderr,
                            "[TCP][WARN] renew lease failed: client=%s server_key=%s session=%s error=%s\n",
                            client_label.c_str(), parts[1].c_str(), parts[2].c_str(), error.c_str());
                    tcp_config_log_warn("续租失败: client=" + client_label +
                                        " server_key=" + parts[1] +
                                        " session=" + parts[2] +
                                        " error=" + error);
                    json_response = make_status_json(status_from_error(error), error, canonical_node_key(*node));
                }
            }

            send_tcp_response(client_fd, json_response, "RENEW_LEASE", request.c_str());
        }
    }
    else if (!parts.empty() && parts[0] == "RELEASE_LEASE") {
        if (parts.size() < 3) {
            string json_response = make_status_json(ip_tunnel::kStatusInvalidRequest,
                                                    "usage: RELEASE_LEASE <server_key> <session_uuid>");
            send_tcp_response(client_fd, json_response, "RELEASE_LEASE/usage", request.c_str());
        } else {
            string json_response;
            lock_guard<mutex> lock(g_servers_mutex);
            const NodeConfig* node = find_node_by_key_locked(parts[1]);
            if (node == NULL) {
                json_response = make_status_json(ip_tunnel::kStatusServerNotFound, "node not found", parts[1]);
            } else if (g_ip_pool_manager.ReleaseLease(canonical_node_key(*node), parts[2])) {
                json_response = make_status_json(ip_tunnel::kStatusOk, "lease released", canonical_node_key(*node));
            } else {
                json_response = make_status_json(ip_tunnel::kStatusLeaseNotFound, "lease not found", canonical_node_key(*node));
            }

            send_tcp_response(client_fd, json_response, "RELEASE_LEASE", request.c_str());
        }
    }
    else {
        // 未知请求
        const char* error_msg = "{\"error\":\"Unknown request\"}";
        string json_response(error_msg);
        send_tcp_response(client_fd, json_response, "UNKNOWN", request.c_str());
        fprintf(stderr, "[TCP] 未知请求: %s\n", request.c_str());
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

        tcp_config_tracef("[TCP] 新连接来自 %s:%d\n", client_ip, client_port);

        // 直接处理请求（简单实现，不使用线程池）
        string client_label = string(client_ip) + ":" + to_string(client_port);
        handle_tcp_request(client_fd, client_label);
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
        printf("✓ 配置重载成功，当前节点数量: %zu\n", g_nodes.size());

        lock_guard<mutex> lock(g_servers_mutex);
        printf("\n当前网络配置:\n");
        printf("------------------------------------\n");
        printf("  隧道端口: %d\n", g_network.tunnel_port);
        printf("  虚拟网段: %s\n", g_network.virtual_subnet.c_str());
        printf("  虚拟网关: %s\n", g_network.virtual_gateway.c_str());
        printf("  公网入口: %s\n", g_network.tunnel_server_ip.c_str());
        printf("  节点列表:\n");
        for (const auto& s : g_nodes) {
            printf("    [%d] %s -> %s\n", s.id, s.name.c_str(), s.server_virtual_ip.c_str());
        }
        printf("------------------------------------\n\n");

        return true;
    } else {
        fprintf(stderr, "✗ 配置重载失败\n");
        return false;
    }
}

// 配置文件监控线程
bool query_active_tcp_config_lease(const std::string& server_key,
                                   const std::string& session_uuid,
                                   IPPoolManager::LeaseRecord* out_record,
                                   std::string* error) {
    lock_guard<mutex> lock(g_servers_mutex);
    if (!server_key.empty()) {
        return g_ip_pool_manager.GetLease(server_key, session_uuid, out_record, error);
    }

    for (size_t i = 0; i < g_nodes.size(); ++i) {
        IPPoolManager::LeaseRecord lease_record;
        string lease_error;
        if (!g_ip_pool_manager.GetLease(canonical_node_key(g_nodes[i]),
                                        session_uuid,
                                        &lease_record,
                                        &lease_error)) {
            continue;
        }

        if (out_record != NULL) {
            *out_record = lease_record;
        }
        if (error != NULL) {
            error->clear();
        }
        return true;
    }

    if (error != NULL) {
        *error = "lease not found";
    }
    return false;
}

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

