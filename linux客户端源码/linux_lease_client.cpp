#include "linux_lease_client.h"

#include "linux_client_common.h"

#include <netdb.h>
#include <sstream>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

bool LinuxLeaseClient::SendCommand(const std::string& host,
                                   int port,
                                   const std::string& command,
                                   std::string* response,
                                   std::string* error,
                                   bool allow_empty_response) {
    if (response == NULL) {
        if (error != NULL) {
            *error = "response output is null";
        }
        return false;
    }
    response->clear();

    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = NULL;
    const std::string port_str = std::to_string(port);
    int ret = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (ret != 0) {
        if (error != NULL) {
            *error = "cannot resolve lease server: " + host;
        }
        return false;
    }

    int sock = -1;
    bool connected = false;
    for (addrinfo* rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;
        }

        timeval timeout = {};
        timeout.tv_sec = 15;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            connected = true;
            break;
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(result);

    if (!connected || sock < 0) {
        if (error != NULL) {
            *error = "cannot connect to lease server: " + host + ":" + port_str;
        }
        return false;
    }

    if (send(sock, command.data(), command.size(), 0) != (ssize_t)command.size()) {
        if (error != NULL) {
            *error = "send lease command failed";
        }
        close(sock);
        return false;
    }

    char buffer[4096];
    while (true) {
        ssize_t n = recv(sock, buffer, sizeof(buffer), 0);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            break;
        }
        response->append(buffer, (size_t)n);
    }

    close(sock);

    if (response->empty()) {
        if (allow_empty_response) {
            return true;
        }
        if (error != NULL) {
            *error = "lease server returned empty response";
        }
        return false;
    }
    return true;
}

bool LinuxLeaseClient::ParseLeaseGrant(const std::string& json,
                                       ip_tunnel::LeaseGrant* lease,
                                       std::string* error) {
    if (lease == NULL) {
        if (error != NULL) {
            *error = "lease output is null";
        }
        return false;
    }

    *lease = ip_tunnel::LeaseGrant();
    lease->status = (ip_tunnel::StatusCode)ExtractJsonInt(json, "status", (int)ip_tunnel::kStatusInvalidRequest);
    lease->message = ExtractJsonString(json, "message");
    lease->virtual_ip = ExtractJsonString(json, "virtual_ip");
    lease->subnet_mask = ExtractJsonString(json, "subnet_mask");
    lease->gateway_ip = ExtractJsonString(json, "gateway_ip");
    lease->server_virtual_ip = ExtractJsonString(json, "server_virtual_ip");
    lease->mtu = (uint16_t)ExtractJsonInt(json, "mtu", (int)ip_tunnel::kDefaultMtu);
    lease->lease_seconds = (uint32_t)ExtractJsonInt(json, "lease_seconds", (int)ip_tunnel::kDefaultLeaseSeconds);
    lease->reused_previous_ip = ExtractJsonBool(json, "reused_previous_ip", false);

    std::vector<std::string> routes = ExtractJsonStringArray(json, "routes");
    for (size_t i = 0; i < routes.size(); ++i) {
        lease->routes.push_back(ip_tunnel::RouteEntry(routes[i]));
    }

    if (lease->status != ip_tunnel::kStatusOk) {
        if (error != NULL) {
            *error = "lease request failed: " + lease->message;
        }
        return false;
    }

    if (lease->virtual_ip.empty() || lease->subnet_mask.empty() || lease->gateway_ip.empty() ||
        lease->server_virtual_ip.empty()) {
        if (error != NULL) {
            *error = "lease response missing required fields";
        }
        return false;
    }

    return true;
}

bool LinuxLeaseClient::RequestLease(const std::string& api_url,
                                    int api_port,
                                    const ip_tunnel::LeaseRequest& request,
                                    ip_tunnel::LeaseGrant* lease,
                                    std::string* error) {
    std::ostringstream command;
    command << "LEASE_IP " << request.server_key << " " << request.session_uuid << " " << request.client_id;
    if (!request.preferred_ip.empty()) {
        command << " " << request.preferred_ip;
    }
    command << "\n";

    std::string response;
    if (!SendCommand(api_url, api_port, command.str(), &response, error)) {
        return false;
    }
    return ParseLeaseGrant(response, lease, error);
}

bool LinuxLeaseClient::RenewLease(const std::string& api_url,
                                  int api_port,
                                  const std::string& server_key,
                                  const std::string& session_uuid,
                                  ip_tunnel::LeaseGrant* lease,
                                  std::string* error) {
    std::ostringstream command;
    command << "RENEW_LEASE " << server_key << " " << session_uuid << "\n";

    std::string response;
    if (!SendCommand(api_url, api_port, command.str(), &response, error)) {
        return false;
    }
    return ParseLeaseGrant(response, lease, error);
}

bool LinuxLeaseClient::ReleaseLease(const std::string& api_url,
                                    int api_port,
                                    const std::string& server_key,
                                    const std::string& session_uuid,
                                    std::string* error) {
    std::ostringstream command;
    command << "RELEASE_LEASE " << server_key << " " << session_uuid << "\n";

    std::string response;
    if (!SendCommand(api_url, api_port, command.str(), &response, error, true)) {
        return false;
    }

    if (response.empty()) {
        return true;
    }

    int status = ExtractJsonInt(response, "status", (int)ip_tunnel::kStatusInvalidRequest);
    if (status != (int)ip_tunnel::kStatusOk) {
        if (error != NULL) {
            *error = "释放租约失败: " + ExtractJsonString(response, "message");
        }
        return false;
    }
    return true;
}
