/*
 * IP租约客户端
 * 负责向配置服务器申请、续租、释放虚拟IP
 */

#pragma once

#include "ip_lease_protocol.h"

#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

class IPLeaseClient {
public:
    IPLeaseClient();
    ~IPLeaseClient();

    bool RequestLease(const std::string& api_url,
                      int api_port,
                      const ip_tunnel::LeaseRequest& request,
                      ip_tunnel::LeaseGrant* lease,
                      std::wstring* error_msg);

    bool RenewLease(const std::string& api_url,
                    int api_port,
                    const std::string& server_key,
                    const std::string& session_uuid,
                    ip_tunnel::LeaseGrant* lease,
                    std::wstring* error_msg);

    bool ReleaseLease(const std::string& api_url,
                      int api_port,
                      const std::string& server_key,
                      const std::string& session_uuid,
                      std::wstring* error_msg);

private:
    std::wstring StringToWString(const std::string& str);
    bool SendCommand(const std::string& host,
                     int port,
                     const std::string& command,
                     std::string& response,
                     std::wstring* error_msg,
                     bool allow_empty_response = false);
    bool ParseLeaseGrant(const std::string& json,
                         ip_tunnel::LeaseGrant* lease,
                         std::wstring* error_msg);

    static std::string ExtractJsonString(const std::string& json, const std::string& key);
    static int ExtractJsonInt(const std::string& json, const std::string& key, int default_value);
    static bool ExtractJsonBool(const std::string& json, const std::string& key, bool default_value);
};
