/*
 * HTTP客户端模块 - 使用WinHTTP API
 * 用于获取服务器列表配置
 */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

// 服务器信息结构
struct ServerInfo {
    int id;
    std::wstring name;           // 使用wstring支持中文
    std::string game_server_ip;
    std::string tunnel_server_ip;
    int tunnel_port;
    std::string download_url;    // 客户端下载地址
};

// HTTP客户端类
class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    // 获取服务器列表
    // api_url: API地址 (如 "config.server.com")
    // api_port: API端口 (如 8080)
    // path: API路径 (如 "/api/servers")
    // servers: 输出服务器列表
    // 返回: 成功返回true,失败返回false
    bool GetServerList(const std::string& api_url,
                      int api_port,
                      const std::string& path,
                      std::vector<ServerInfo>& servers,
                      std::wstring& error_msg);

private:
    // 发送HTTP GET请求并获取响应
    bool HttpGet(const std::wstring& host,
                int port,
                const std::wstring& path,
                std::string& response,
                std::wstring& error_msg);

    // 将std::string转换为std::wstring
    std::wstring StringToWString(const std::string& str);

    // 将std::wstring转换为std::string
    std::string WStringToString(const std::wstring& wstr);
};

#endif // HTTP_CLIENT_H
