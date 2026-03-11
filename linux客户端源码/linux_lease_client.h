#pragma once

#include "ip_lease_protocol.h"

#include <string>

class LinuxLeaseClient {
public:
    bool RequestLease(const std::string& api_url,
                      int api_port,
                      const ip_tunnel::LeaseRequest& request,
                      ip_tunnel::LeaseGrant* lease,
                      std::string* error);

    bool RenewLease(const std::string& api_url,
                    int api_port,
                    const std::string& server_key,
                    const std::string& session_uuid,
                    ip_tunnel::LeaseGrant* lease,
                    std::string* error);

    bool ReleaseLease(const std::string& api_url,
                      int api_port,
                      const std::string& server_key,
                      const std::string& session_uuid,
                      std::string* error);

private:
    bool SendCommand(const std::string& host,
                     int port,
                     const std::string& command,
                     std::string* response,
                     std::string* error);
    bool ParseLeaseGrant(const std::string& json,
                         ip_tunnel::LeaseGrant* lease,
                         std::string* error);
};