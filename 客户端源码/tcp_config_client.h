/*
 * TCP配置客户端模块 - 替代HTTP客户端
 * 使用纯TCP Socket通信，绕过HTTP备案限制
 */

#ifndef TCP_CONFIG_CLIENT_H
#define TCP_CONFIG_CLIENT_H

#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// 服务器信息结构体
struct ServerInfo {
    int id;
    std::wstring name;
    std::string game_server_ip;
    std::string tunnel_server_ip;
    int tunnel_port;
    std::string download_url;
};

// TCP配置客户端类
class TcpConfigClient {
public:
    TcpConfigClient();
    ~TcpConfigClient();

    // 从TCP服务器获取服务器列表
    // api_url: 服务器域名或IP
    // api_port: 服务器端口
    // servers: 输出的服务器列表
    // error_msg: 错误信息
    bool GetServerList(const std::string& api_url,
                      int api_port,
                      std::vector<ServerInfo>& servers,
                      std::wstring& error_msg);

private:
    // 字符串转换函数
    std::wstring StringToWString(const std::string& str);
    std::string WStringToString(const std::wstring& wstr);

    // TCP连接并获取数据
    bool TcpGetData(const std::string& host,
                   int port,
                   const std::string& request,
                   std::string& response,
                   std::wstring& error_msg);
};

#endif // TCP_CONFIG_CLIENT_H
