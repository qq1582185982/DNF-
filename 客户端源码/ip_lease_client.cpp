/*
 * IP租约客户端实现
 */

#include "ip_lease_client.h"

#include <sstream>

IPLeaseClient::IPLeaseClient() {
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

IPLeaseClient::~IPLeaseClient() {
    WSACleanup();
}

std::wstring IPLeaseClient::StringToWString(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstr(size_needed - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);
    return wstr;
}

bool IPLeaseClient::SendCommand(const std::string& host,
                                int port,
                                const std::string& command,
                                std::string& response,
                                std::wstring* error_msg) {
    SOCKET sock = INVALID_SOCKET;
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    struct addrinfo* rp = NULL;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const std::string port_str = std::to_string(port);
    int ret = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (ret != 0) {
        if (error_msg) {
            *error_msg = L"无法解析租约服务器域名: " + StringToWString(host);
        }
        return false;
    }

    DWORD timeout = 15000;
    int last_error = 0;
    bool connected = false;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET) {
            last_error = WSAGetLastError();
            continue;
        }

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        if (connect(sock, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
            connected = true;
            break;
        }

        last_error = WSAGetLastError();
        closesocket(sock);
        sock = INVALID_SOCKET;
    }

    freeaddrinfo(result);
    result = NULL;

    if (!connected || sock == INVALID_SOCKET) {
        if (error_msg) {
            *error_msg = L"无法连接到租约服务器: " + StringToWString(host) + L":" +
                         std::to_wstring(port) + L" (WSA错误=" + std::to_wstring(last_error) + L")";
        }
        return false;
    }

    int sent = send(sock, command.c_str(), (int)command.length(), 0);
    if (sent == SOCKET_ERROR) {
        if (error_msg) {
            *error_msg = L"发送租约命令失败";
        }
        closesocket(sock);
        return false;
    }

    response.clear();
    char buffer[4096];
    int received = 0;
    while ((received = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        response.append(buffer, received);
    }

    if (received == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAETIMEDOUT) {
            if (error_msg) {
                *error_msg = L"接收租约响应失败，错误码: " + std::to_wstring(err);
            }
            closesocket(sock);
            return false;
        }
    }

    closesocket(sock);

    if (response.empty()) {
        if (error_msg) {
            *error_msg = L"租约服务器返回空数据";
        }
        return false;
    }

    return true;
}

std::string IPLeaseClient::ExtractJsonString(const std::string& json, const std::string& key) {
    const std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return "";
    }

    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return "";
    }

    pos = json.find('"', pos);
    if (pos == std::string::npos) {
        return "";
    }

    size_t end = pos + 1;
    while (true) {
        end = json.find('"', end);
        if (end == std::string::npos) {
            return "";
        }
        if (json[end - 1] != '\\') {
            break;
        }
        end++;
    }

    return json.substr(pos + 1, end - pos - 1);
}

int IPLeaseClient::ExtractJsonInt(const std::string& json,
                                  const std::string& key,
                                  int default_value) {
    const std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return default_value;
    }

    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return default_value;
    }

    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
        pos++;
    }

    return atoi(json.c_str() + pos);
}

bool IPLeaseClient::ExtractJsonBool(const std::string& json,
                                    const std::string& key,
                                    bool default_value) {
    const std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return default_value;
    }

    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return default_value;
    }

    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
        pos++;
    }

    if (json.compare(pos, 4, "true") == 0) {
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        return false;
    }
    return default_value;
}

bool IPLeaseClient::ParseLeaseGrant(const std::string& json,
                                    ip_tunnel::LeaseGrant* lease,
                                    std::wstring* error_msg) {
    if (!lease) {
        if (error_msg) {
            *error_msg = L"lease输出参数为空";
        }
        return false;
    }

    *lease = ip_tunnel::LeaseGrant();
    lease->status = (ip_tunnel::StatusCode)ExtractJsonInt(json, "status", (int)ip_tunnel::kStatusInvalidRequest);
    lease->message = ExtractJsonString(json, "message");

    if (lease->status != ip_tunnel::kStatusOk) {
        if (error_msg) {
            *error_msg = L"租约请求失败: " + StringToWString(lease->message);
        }
        return false;
    }

    lease->virtual_ip = ExtractJsonString(json, "virtual_ip");
    lease->subnet_mask = ExtractJsonString(json, "subnet_mask");
    lease->gateway_ip = ExtractJsonString(json, "gateway_ip");

    int mtu = ExtractJsonInt(json, "mtu", (int)ip_tunnel::kDefaultMtu);
    if (mtu > 0) {
        lease->mtu = (uint16_t)mtu;
    }

    int lease_seconds = ExtractJsonInt(json, "lease_seconds", (int)ip_tunnel::kDefaultLeaseSeconds);
    if (lease_seconds > 0) {
        lease->lease_seconds = (uint32_t)lease_seconds;
    }

    lease->reused_previous_ip = ExtractJsonBool(json, "reused_previous_ip", false);

    size_t routes_pos = json.find("\"routes\"");
    if (routes_pos != std::string::npos) {
        size_t array_start = json.find('[', routes_pos);
        size_t array_end = json.find(']', array_start);
        if (array_start != std::string::npos && array_end != std::string::npos && array_end > array_start) {
            size_t pos = array_start + 1;
            while (pos < array_end) {
                size_t quote_start = json.find('"', pos);
                if (quote_start == std::string::npos || quote_start >= array_end) {
                    break;
                }

                size_t quote_end = json.find('"', quote_start + 1);
                if (quote_end == std::string::npos || quote_end > array_end) {
                    break;
                }

                lease->routes.push_back(ip_tunnel::RouteEntry(json.substr(quote_start + 1, quote_end - quote_start - 1)));
                pos = quote_end + 1;
            }
        }
    }

    if (lease->virtual_ip.empty() || lease->subnet_mask.empty() || lease->gateway_ip.empty()) {
        if (error_msg) {
            *error_msg = L"租约响应字段不完整";
        }
        return false;
    }

    return true;
}

bool IPLeaseClient::RequestLease(const std::string& api_url,
                                 int api_port,
                                 const ip_tunnel::LeaseRequest& request,
                                 ip_tunnel::LeaseGrant* lease,
                                 std::wstring* error_msg) {
    if (request.server_key.empty() || request.session_uuid.empty() || request.client_id.empty()) {
        if (error_msg) {
            *error_msg = L"租约请求缺少必要参数";
        }
        return false;
    }

    std::ostringstream command;
    command << "LEASE_IP " << request.server_key << " " << request.session_uuid << " " << request.client_id;
    if (!request.preferred_ip.empty()) {
        command << " " << request.preferred_ip;
    }
    command << "\n";

    std::string response;
    if (!SendCommand(api_url, api_port, command.str(), response, error_msg)) {
        return false;
    }

    return ParseLeaseGrant(response, lease, error_msg);
}

bool IPLeaseClient::RenewLease(const std::string& api_url,
                               int api_port,
                               const std::string& server_key,
                               const std::string& session_uuid,
                               ip_tunnel::LeaseGrant* lease,
                               std::wstring* error_msg) {
    if (server_key.empty() || session_uuid.empty()) {
        if (error_msg) {
            *error_msg = L"续租请求缺少必要参数";
        }
        return false;
    }

    std::ostringstream command;
    command << "RENEW_LEASE " << server_key << " " << session_uuid << "\n";

    std::string response;
    if (!SendCommand(api_url, api_port, command.str(), response, error_msg)) {
        return false;
    }

    return ParseLeaseGrant(response, lease, error_msg);
}

bool IPLeaseClient::ReleaseLease(const std::string& api_url,
                                 int api_port,
                                 const std::string& server_key,
                                 const std::string& session_uuid,
                                 std::wstring* error_msg) {
    if (server_key.empty() || session_uuid.empty()) {
        if (error_msg) {
            *error_msg = L"释放租约请求缺少必要参数";
        }
        return false;
    }

    std::ostringstream command;
    command << "RELEASE_LEASE " << server_key << " " << session_uuid << "\n";

    std::string response;
    if (!SendCommand(api_url, api_port, command.str(), response, error_msg)) {
        return false;
    }

    const int status = ExtractJsonInt(response, "status", (int)ip_tunnel::kStatusInvalidRequest);
    if (status != (int)ip_tunnel::kStatusOk) {
        if (error_msg) {
            *error_msg = L"释放租约失败: " + StringToWString(ExtractJsonString(response, "message"));
        }
        return false;
    }

    return true;
}
