#pragma once

#include "linux_client_common.h"

#include <string>
#include <vector>

class LinuxConfigClient {
public:
    bool GetServerList(const std::string& api_url,
                       int api_port,
                       std::vector<LinuxServerInfo>* servers,
                       std::string* error);

private:
    bool TcpGetData(const std::string& host,
                    int port,
                    const std::string& request,
                    std::string* response,
                    std::string* error);
};