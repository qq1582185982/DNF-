#include "linux_config_client.h"

#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

bool LinuxConfigClient::TcpGetData(const std::string& host,
                                   int port,
                                   const std::string& request,
                                   std::string* response,
                                   std::string* error) {
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
            *error = "getaddrinfo failed for " + host;
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
            *error = "连接失败: " + host + ":" + port_str;
        }
        return false;
    }

    if (send(sock, request.data(), request.size(), 0) != (ssize_t)request.size()) {
        if (error != NULL) {
            *error = "发送请求失败";
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
        if (error != NULL) {
            *error = "服务器返回为空";
        }
        return false;
    }
    return true;
}

bool LinuxConfigClient::GetServerList(const std::string& api_url,
                                      int api_port,
                                      std::vector<LinuxServerInfo>* servers,
                                      std::string* error) {
    std::string response;
    if (!TcpGetData(api_url, api_port, "GET_SERVERS\n", &response, error)) {
        return false;
    }
    return ParseServerListJson(response, servers, error);
}
