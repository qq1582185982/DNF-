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
#include <sstream>
#include <thread>

namespace {

struct Options {
    std::string api_url;
    int api_port;
    std::string server_key;
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
                *error = "invalid config line " + std::to_string(line_number) + ": " + line;
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
        << "  --server-key KEY   (optional if GET_SERVERS returns exactly 1 server)\n"
        << "  --client-id ID     (optional, defaults to hostname)\n\n"
        << "Options:\n"
        << "  --config FILE          Load key=value config file\n"
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
            LogError("load config failed: " + config_error);
            return false;
        }
        options->config_path = detected_config;
    } else if (!options->config_path.empty()) {
        LogError("config file not found: " + options->config_path);
        return false;
    }

    std::map<std::string, std::string*> string_flags;
    string_flags["--api-url"] = &options->api_url;
    string_flags["--server-key"] = &options->server_key;
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
                    const std::string& server_key,
                    LinuxServerInfo* out_server) {
    if (out_server == NULL) {
        return false;
    }

    for (size_t i = 0; i < servers.size(); ++i) {
        if (std::to_string(servers[i].id) == server_key || servers[i].name == server_key) {
            *out_server = servers[i];
            return true;
        }
    }
    return false;
}

}  // namespace

int main(int argc, char** argv) {
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

    LogInfo("Linux tunnel client starting");
    LogInfo("session_uuid=" + options.session_uuid);
    if (!options.config_path.empty()) {
        LogInfo("config=" + options.config_path);
    }
    LogInfo("client_id=" + options.client_id);

    LinuxConfigClient config_client;
    std::vector<LinuxServerInfo> servers;
    std::string error;
    if (!config_client.GetServerList(options.api_url, options.api_port, &servers, &error)) {
        LogError("GET_SERVERS failed: " + error);
        return 1;
    }

    LinuxServerInfo server_info;
    if (options.server_key.empty()) {
        if (servers.size() == 1) {
            options.server_key = std::to_string(servers[0].id);
            LogInfo("server_key auto selected: " + options.server_key + " (" + servers[0].name + ")");
        } else {
            LogError("server_key is required when GET_SERVERS returns multiple servers");
            return 1;
        }
    }

    if (!FindServerInfo(servers, options.server_key, &server_info)) {
        LogError("server_key not found: " + options.server_key);
        return 1;
    }

    if (options.tunnel_host.empty()) {
        options.tunnel_host = server_info.tunnel_server_ip;
    }
    if (options.tunnel_port <= 0) {
        options.tunnel_port = server_info.tunnel_port;
    }

    LinuxLeaseClient lease_client;
    ip_tunnel::LeaseRequest lease_request;
    lease_request.server_key = options.server_key;
    lease_request.session_uuid = options.session_uuid;
    lease_request.client_id = options.client_id;
    lease_request.preferred_ip = options.preferred_ip;

    ip_tunnel::LeaseGrant lease;
    if (!lease_client.RequestLease(options.api_url, options.api_port, lease_request, &lease, &error)) {
        LogError("LEASE_IP failed: " + error);
        return 1;
    }

    LogInfo("lease granted: virtual_ip=" + lease.virtual_ip +
            " gateway=" + lease.gateway_ip +
            " server_virtual_ip=" + lease.server_virtual_ip);

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

    LinuxTunManager tun_manager;
    if (!tun_manager.Setup(tun_config, &error)) {
        LogError("TUN setup failed: " + error);
        lease_client.ReleaseLease(options.api_url, options.api_port, options.server_key, options.session_uuid, NULL);
        return 1;
    }

    LogInfo("TUN ready: if=" + tun_manager.GetIfName() + " ip=" + lease.virtual_ip);

    LinuxPacketTunnelClient packet_client(options.tunnel_host,
                                          (uint16_t)options.tunnel_port,
                                          options.session_uuid,
                                          lease.virtual_ip,
                                          lease.mtu,
                                          &tun_manager);

    if (!packet_client.Start(&error)) {
        LogError("packet tunnel start failed: " + error);
        tun_manager.Cleanup();
        lease_client.ReleaseLease(options.api_url, options.api_port, options.server_key, options.session_uuid, NULL);
        return 1;
    }

    LogInfo("packet tunnel connected: " + options.tunnel_host + ":" + std::to_string(options.tunnel_port));

    std::atomic<bool> renew_stop(false);
    std::thread renew_thread([&]() {
        while (!renew_stop && !g_linux_client_stop) {
            uint32_t wait_seconds = lease.lease_seconds / 2;
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
            if (!lease_client.RenewLease(options.api_url, options.api_port, options.server_key,
                                         options.session_uuid, &renewed, &renew_error)) {
                LogWarn("lease renew failed: " + renew_error);
                continue;
            }

            lease = renewed;
            LogInfo("lease renewed: virtual_ip=" + lease.virtual_ip);
        }
    });

    while (!g_linux_client_stop && packet_client.IsConnected()) {
        usleep(200 * 1000);
    }

    renew_stop = true;
    packet_client.Stop();
    if (renew_thread.joinable()) {
        renew_thread.join();
    }
    tun_manager.Cleanup();

    std::string release_error;
    if (!lease_client.ReleaseLease(options.api_url, options.api_port, options.server_key,
                                   options.session_uuid, &release_error)) {
        LogWarn("release lease failed: " + release_error);
    } else {
        LogInfo("lease released");
    }

    LogInfo("Linux tunnel client stopped");
    return 0;
}
