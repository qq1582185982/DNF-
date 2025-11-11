/*
 * HTTP客户端模块实现
 */

#include "http_client.h"
#include <sstream>
#include <locale>
#include <codecvt>

// 前向声明JSON解析函数
extern std::vector<ServerInfo> parse_server_list(const std::string& json_str);

HttpClient::HttpClient() {
}

HttpClient::~HttpClient() {
}

std::wstring HttpClient::StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstr(size_needed - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);
    return wstr;
}

std::string HttpClient::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::string str(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size_needed, NULL, NULL);
    return str;
}

bool HttpClient::HttpGet(const std::wstring& host,
                         int port,
                         const std::wstring& path,
                         std::string& response,
                         std::wstring& error_msg) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    bool success = false;

    try {
        // 1. 初始化WinHTTP会话
        hSession = WinHttpOpen(L"DNF Proxy Client/1.0",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS,
                              0);

        if (!hSession) {
            error_msg = L"无法初始化HTTP会话";
            return false;
        }

        // 设置超时: 5秒连接超时, 10秒接收超时
        int timeout_connect = 5000;  // 5秒
        int timeout_receive = 10000; // 10秒
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout_connect, sizeof(timeout_connect));
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout_receive, sizeof(timeout_receive));

        // 2. 连接到服务器
        hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect) {
            error_msg = L"无法连接到服务器: " + host;
            WinHttpCloseHandle(hSession);
            return false;
        }

        // 3. 创建HTTP请求
        hRequest = WinHttpOpenRequest(hConnect,
                                     L"GET",
                                     path.c_str(),
                                     NULL,
                                     WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     0);

        if (!hRequest) {
            error_msg = L"无法创建HTTP请求";
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // 4. 发送请求
        if (!WinHttpSendRequest(hRequest,
                               WINHTTP_NO_ADDITIONAL_HEADERS,
                               0,
                               WINHTTP_NO_REQUEST_DATA,
                               0,
                               0,
                               0)) {
            error_msg = L"发送HTTP请求失败";
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // 5. 接收响应
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            error_msg = L"接收HTTP响应失败";
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // 6. 检查HTTP状态码
        DWORD status_code = 0;
        DWORD status_code_size = sizeof(status_code);
        WinHttpQueryHeaders(hRequest,
                           WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           NULL,
                           &status_code,
                           &status_code_size,
                           NULL);

        if (status_code != 200) {
            wchar_t buf[100];
            swprintf(buf, 100, L"HTTP状态码错误: %d", status_code);
            error_msg = buf;
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // 7. 读取响应数据
        response.clear();
        DWORD bytes_available = 0;
        DWORD bytes_read = 0;
        char buffer[4096];

        while (WinHttpQueryDataAvailable(hRequest, &bytes_available) && bytes_available > 0) {
            DWORD to_read = (bytes_available < sizeof(buffer)) ? bytes_available : sizeof(buffer);

            if (WinHttpReadData(hRequest, buffer, to_read, &bytes_read)) {
                response.append(buffer, bytes_read);
            } else {
                error_msg = L"读取HTTP响应数据失败";
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return false;
            }
        }

        success = true;

    } catch (...) {
        error_msg = L"HTTP请求过程中发生异常";
        success = false;
    }

    // 8. 清理资源
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return success;
}

bool HttpClient::GetServerList(const std::string& api_url,
                               int api_port,
                               const std::string& path,
                               std::vector<ServerInfo>& servers,
                               std::wstring& error_msg) {
    // 1. 转换为宽字符
    std::wstring whost = StringToWString(api_url);
    std::wstring wpath = StringToWString(path);

    // 2. 发送HTTP GET请求
    std::string response;
    if (!HttpGet(whost, api_port, wpath, response, error_msg)) {
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
