/*
 * TCP配置客户端模块实现
 */

#include "tcp_config_client.h"
#include <sstream>

// 前向声明JSON解析函数
extern std::vector<ServerInfo> parse_server_list(const std::string& json_str);

TcpConfigClient::TcpConfigClient() {
    // 初始化Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

TcpConfigClient::~TcpConfigClient() {
    // 清理Winsock
    WSACleanup();
}

std::wstring TcpConfigClient::StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstr(size_needed - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);
    return wstr;
}

std::string TcpConfigClient::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string str(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size_needed, NULL, NULL);
    return str;
}

bool TcpConfigClient::TcpGetData(const std::string& host,
                                 int port,
                                 const std::string& request,
                                 std::string& response,
                                 std::wstring& error_msg) {
    SOCKET sock = INVALID_SOCKET;
    struct addrinfo hints, *result = NULL;

    try {
        // 1. 解析域名/IP
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        std::string port_str = std::to_string(port);
        int ret = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
        if (ret != 0) {
            error_msg = L"无法解析域名: " + StringToWString(host);
            return false;
        }

        // 2. 创建Socket
        sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock == INVALID_SOCKET) {
            error_msg = L"创建Socket失败";
            freeaddrinfo(result);
            return false;
        }

        // 设置超时 (15秒)
        DWORD timeout = 15000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        // 3. 连接到服务器
        if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
            error_msg = L"无法连接到服务器: " + StringToWString(host) + L":" + std::to_wstring(port);
            closesocket(sock);
            freeaddrinfo(result);
            return false;
        }

        freeaddrinfo(result);

        // 4. 发送请求
        int sent = send(sock, request.c_str(), (int)request.length(), 0);
        if (sent == SOCKET_ERROR) {
            error_msg = L"发送请求失败";
            closesocket(sock);
            return false;
        }

        // 5. 接收响应
        response.clear();
        char buffer[4096];
        int received;

        while ((received = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
            response.append(buffer, received);
        }

        if (received == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSAETIMEDOUT) {
                error_msg = L"接收数据失败，错误码: " + std::to_wstring(err);
                closesocket(sock);
                return false;
            }
        }

        closesocket(sock);

        if (response.empty()) {
            error_msg = L"服务器返回空数据";
            return false;
        }

        return true;

    } catch (...) {
        error_msg = L"TCP请求过程中发生异常";
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
        if (result) {
            freeaddrinfo(result);
        }
        return false;
    }
}

bool TcpConfigClient::GetServerList(const std::string& api_url,
                                    int api_port,
                                    std::vector<ServerInfo>& servers,
                                    std::wstring& error_msg) {
    // 1. 构建TCP请求 (简单的协议: "GET_SERVERS\n")
    std::string request = "GET_SERVERS\n";

    // 2. 发送TCP请求并接收响应
    std::string response;
    if (!TcpGetData(api_url, api_port, request, response, error_msg)) {
        return false;
    }

    // 3. 检查响应是否为空
    if (response.empty()) {
        error_msg = L"服务器返回空数据";
        return false;
    }

    // 4. 解析JSON响应
    try {
        servers = parse_server_list(response);

        if (servers.empty()) {
            error_msg = L"服务器列表为空";
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        error_msg = L"解析JSON失败: " + StringToWString(e.what());
        return false;
    } catch (...) {
        error_msg = L"解析JSON时发生未知错误";
        return false;
    }
}
