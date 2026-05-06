#include "ip_lease_protocol.h"
#include "linux_client_common.h"
#include "linux_config_client.h"
#include "linux_lease_client.h"
#include "linux_packet_tunnel_client.h"
#include "linux_tun_manager.h"

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

namespace {

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

std::string Trim(const std::string& value) {
    size_t start = 0;
    while (start < value.size() && isspace((unsigned char)value[start])) {
        ++start;
    }

    size_t end = value.size();
    while (end > start && isspace((unsigned char)value[end - 1])) {
        --end;
    }

    return value.substr(start, end - start);
}

std::string StripQuotes(const std::string& value) {
    if (value.size() >= 2) {
        char first = value.front();
        char last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return value.substr(1, value.size() - 2);
        }
    }
    return value;
}

std::vector<std::string> GetDefaultConfigPaths() {
    std::vector<std::string> paths;
    paths.push_back("./dnf-linux-client.conf");
    paths.push_back("./client.conf");
    paths.push_back("/etc/dnf-linux-client.conf");
    paths.push_back("/etc/dnf-linux-client/client.conf");
    return paths;
}

std::string DetectConfigPath(const std::string& requested_path) {
    if (!requested_path.empty()) {
        std::ifstream requested(requested_path.c_str());
        if (requested.good()) {
            return requested_path;
        }
        return std::string();
    }

    std::vector<std::string> paths = GetDefaultConfigPaths();
    for (size_t i = 0; i < paths.size(); ++i) {
        std::ifstream file(paths[i].c_str());
        if (file.good()) {
            return paths[i];
        }
    }

    return std::string();
}

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
        char hostname[256] = {};
        if (gethostname(hostname, sizeof(hostname) - 1) == 0 && hostname[0] != '\0') {
            options->client_id = hostname;
        } else {
            options->client_id = "linux-node";
        }
    }
}

void SignalHandler(int) {
    g_linux_client_stop = true;
}

void PrintUsage() {
    std::cout
        << "Usage:\n"
        << "  ./dnf-linux-client [--config FILE] [options]\n\n"
        << "Config search order:\n"
        << "  ./dnf-linux-client.conf\n"
        << "  ./client.conf\n"
        << "  /etc/dnf-linux-client.conf\n"
        << "  /etc/dnf-linux-client/client.conf\n\n"
        << "Required when no config file is present:\n"
        << "  --api-url HOST --api-port PORT\n"
        << "  --server-virtual-ip IP  (recommended when multiple nodes exist)\n"
        << "  --client-id ID     (optional, defaults to hostname)\n\n"
        << "Options:\n"
        << "  --config FILE          Load key=value config file\n"
        << "  --server-virtual-ip IP Select node by server virtual IP\n"
        << "  --preferred-ip IP      Request a preferred virtual IP\n"
        << "  --if-name NAME         TUN interface name, default dnfcli0\n"
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

    if (options->api_url.empty() || options->api_port <= 0) {
        return false;
    }

    return true;
}

bool FindServerInfo(const std::vector<LinuxServerInfo>& servers,
                    const std::string& server_selector,
                    LinuxServerInfo* out_server) {
    if (out_server == NULL) {
        return false;
    }

    for (size_t i = 0; i < servers.size(); ++i) {
        if (std::to_string(servers[i].id) == server_selector ||
            servers[i].name == server_selector ||
            servers[i].server_virtual_ip == server_selector) {
            *out_server = servers[i];
            return true;
        }
    }
    return false;
}

LinuxTunConfig BuildTunConfig(const Options& options,
                              const LinuxServerInfo& server_info,
                              const ip_tunnel::LeaseGrant& lease) {
    LinuxTunConfig tun_config;
    tun_config.if_name = options.if_name;
    tun_config.virtual_ip = lease.virtual_ip;
    tun_config.subnet_mask = lease.subnet_mask;
    tun_config.mtu = lease.mtu;
    for (size_t i = 0; i < lease.routes.size(); ++i) {
        tun_config.routes.push_back(lease.routes[i].cidr);
    }
    if (tun_config.routes.empty() && !server_info.virtual_subnet.empty()) {
        tun_config.routes.push_back(server_info.virtual_subnet);
    }
    return tun_config;
}

}  // namespace

int main(int argc, char** argv) {
    SetLogLevel(GetLogLevel());
    Options options;
    if (!ParseArgs(argc, argv, &options)) {
        PrintUsage();
        if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
            return 0;
        }
        return 1;
    }

    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    LogInfo("Linux 隧道客户端启动");
    LogInfo("日志级别=" + GetLogLevel());
    LogInfo("会话UUID=" + options.session_uuid);
    if (!options.config_path.empty()) {
        LogInfo("配置文件=" + options.config_path);
    }
    LogInfo("客户端ID=" + options.client_id);

    std::string selected_server_key = options.server_key;
    if (selected_server_key.empty() && !options.server_virtual_ip.empty()) {
        selected_server_key = options.server_virtual_ip;
    }

    if (options.preferred_ip.empty() && !options.server_virtual_ip.empty()) {
        options.preferred_ip = options.server_virtual_ip;
    }
    const unsigned int kInitialRetryDelaySeconds = 2;
    unsigned int startup_attempt = 0;
    LinuxConfigClient config_client;
    LinuxLeaseClient lease_client;

    while (!g_linux_client_stop) {
        ++startup_attempt;

        std::vector<LinuxServerInfo> servers;
        std::string error;
        if (!config_client.GetServerList(options.api_url, options.api_port, &servers, &error)) {
            LogWarn("获取服务器列表失败，" +
                    std::to_string(kInitialRetryDelaySeconds) +
                    "秒后重试: " + error);
            sleep(kInitialRetryDelaySeconds);
            continue;
        }

        LinuxServerInfo server_info;
        std::string effective_selector = selected_server_key;
        if (effective_selector.empty()) {
            if (servers.size() == 1) {
                effective_selector = std::to_string(servers[0].id);
                LogInfo("已自动选择节点: " + effective_selector + " (" + servers[0].name + ")");
            } else {
                LogWarn("未指定节点且获取服务器列表返回了 " +
                        std::to_string(servers.size()) +
                        " 个节点，" +
                        std::to_string(kInitialRetryDelaySeconds) + "秒后重试");
                sleep(kInitialRetryDelaySeconds);
                continue;
            }
        }

        if (!FindServerInfo(servers, effective_selector, &server_info)) {
            LogWarn("在服务器列表中未找到节点，" +
                    std::to_string(kInitialRetryDelaySeconds) +
                    "秒后重试: " + effective_selector);
            sleep(kInitialRetryDelaySeconds);
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
        if (!lease_client.RequestLease(options.api_url, options.api_port, lease_request, &lease, &error)) {
            LogWarn("申请租约失败，" +
                    std::to_string(kInitialRetryDelaySeconds) +
                    "秒后重试: " + error);
            sleep(kInitialRetryDelaySeconds);
            continue;
        }

        LogInfo("已获取租约: 虚拟IP=" + lease.virtual_ip +
                " 网关=" + lease.gateway_ip +
                " 服务器虚拟IP=" + lease.server_virtual_ip);

        LinuxTunManager tun_manager;
        LinuxTunConfig tun_config = BuildTunConfig(options, server_info, lease);
        if (!tun_manager.Setup(tun_config, &error)) {
            LogWarn("TUN 配置失败，" +
                    std::to_string(kInitialRetryDelaySeconds) +
                    "秒后重试: " + error);
            lease_client.ReleaseLease(options.api_url, options.api_port, effective_server_key, options.session_uuid, NULL);
            sleep(kInitialRetryDelaySeconds);
            continue;
        }

        LogInfo("TUN 已就绪: 接口=" + tun_manager.GetIfName() + " IP=" + lease.virtual_ip);

        std::unique_ptr<LinuxPacketTunnelClient> packet_client;
        auto start_packet_client = [&](const ip_tunnel::LeaseGrant& current_lease, std::string* start_error) -> bool {
            packet_client.reset(new LinuxPacketTunnelClient(effective_tunnel_host,
                                                            (uint16_t)effective_tunnel_port,
                                                            options.session_uuid,
                                                            options.client_id,
                                                            current_lease.server_virtual_ip,
                                                            current_lease.virtual_ip,
                                                            current_lease.mtu,
                                                            &tun_manager));
            return packet_client->Start(start_error);
        };

        if (!start_packet_client(lease, &error)) {
            LogWarn("数据隧道启动失败，" +
                    std::to_string(kInitialRetryDelaySeconds) +
                    "秒后重试: " + error);
            tun_manager.Cleanup();
            lease_client.ReleaseLease(options.api_url, options.api_port, effective_server_key, options.session_uuid, NULL);
            sleep(kInitialRetryDelaySeconds);
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
                while (!renew_stop && !g_linux_client_stop) {
                    uint32_t wait_seconds = 0;
                    {
                        std::lock_guard<std::mutex> lock(lease_mutex);
                        wait_seconds = lease.lease_seconds / 2;
                    }
                    if (wait_seconds < 15) {
                        wait_seconds = 15;
                    }

                    for (uint32_t i = 0; i < wait_seconds && !renew_stop && !g_linux_client_stop; ++i) {
                        sleep(1);
                    }
                    if (renew_stop || g_linux_client_stop) {
                        break;
                    }

                    ip_tunnel::LeaseGrant renewed;
                    std::string renew_error;
                    if (!lease_client.RenewLease(options.api_url, options.api_port, effective_server_key,
                                                 options.session_uuid, &renewed, &renew_error)) {
                        renew_failed = true;
                        LogWarn("租约续约失败: " + renew_error);
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

        while (!g_linux_client_stop) {
            if (packet_client && packet_client->IsConnected() && !renew_failed) {
                usleep(200 * 1000);
                continue;
            }

            if (g_linux_client_stop) {
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

            std::string preferred_ip;
            {
                std::lock_guard<std::mutex> lock(lease_mutex);
                preferred_ip = lease.virtual_ip;
            }

            ip_tunnel::LeaseGrant recovered_lease;
            std::string recover_error;
            if (!lease_client.RenewLease(options.api_url, options.api_port, effective_server_key,
                                         options.session_uuid, &recovered_lease, &recover_error)) {
                ip_tunnel::LeaseRequest recover_request;
                recover_request.server_key = effective_server_key;
                recover_request.session_uuid = options.session_uuid;
                recover_request.client_id = options.client_id;
                recover_request.preferred_ip = preferred_ip;

                if (!lease_client.RequestLease(options.api_url, options.api_port, recover_request,
                                               &recovered_lease, &recover_error)) {
                    LogWarn("租约恢复失败: " + recover_error);
                    sleep(2);
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

            LinuxTunConfig recovered_tun_config = BuildTunConfig(options, server_info, recovered_lease);
            if (!tun_manager.Setup(recovered_tun_config, &error)) {
                LogWarn("TUN 重新配置失败: " + error);
                sleep(2);
                continue;
            }

            if (!start_packet_client(recovered_lease, &error)) {
                LogWarn("数据隧道重连失败: " + error);
                sleep(2);
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
        tun_manager.Cleanup();

        std::string release_error;
        if (!lease_client.ReleaseLease(options.api_url, options.api_port, effective_server_key,
                                       options.session_uuid, &release_error)) {
            if (release_error == "lease server returned empty response" ||
                release_error.find("cannot connect to lease server: ") == 0 ||
                release_error.find("send lease command failed") == 0) {
                LogInfo("释放租约时租约服务不可用，已跳过");
            } else {
                LogWarn("释放租约失败: " + release_error);
            }
        } else {
            LogInfo("租约已释放");
        }
    }

    LogInfo("Linux 隧道客户端已停止");
    return 0;
}
