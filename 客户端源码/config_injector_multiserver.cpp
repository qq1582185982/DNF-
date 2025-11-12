/*
 * DNF代理客户端 - 多服务器版配置注入工具 v1.0
 * 内置多服务器客户端二进制,追加API配置生成最终exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <algorithm>
#include <ctime>

#include "embedded_client_multiserver.h"  // 内置多服务器客户端二进制

using namespace std;

// ==================== 工具函数 ====================

// 验证域名格式
bool validate_domain(const string& domain) {
    if (domain.empty()) {
        return false;
    }

    // 域名格式检测
    // 允许字母、数字、连字符、点号,必须包含至少一个点号
    regex domain_pattern("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");
    if (regex_match(domain, domain_pattern) && domain.find('.') != string::npos) {
        return true;
    }

    return false;
}

// 验证端口号
bool validate_port(int port) {
    return port >= 1 && port <= 65535;
}

// 去除字符串首尾空格
string trim(const string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// 将字符串转换为安全的文件名格式
string sanitize_for_filename(const string& str) {
    string safe = str;
    // 替换所有非法文件名字符为下划线
    const string illegal_chars = "<>:\"/\\|?*";
    for (char c : illegal_chars) {
        replace(safe.begin(), safe.end(), c, '_');
    }
    // 限制长度
    if (safe.length() > 50) {
        safe = safe.substr(0, 50);
    }
    return safe;
}

// ==================== 主程序 ====================

int main() {
    // 设置控制台UTF-8编码 (输入和输出)
    SetConsoleCP(CP_UTF8);        // 输入编码
    SetConsoleOutputCP(CP_UTF8);  // 输出编码
    system("chcp 65001 > nul");

    cout << "============================================" << endl;
    cout << "DNF代理客户端 - 多服务器版配置注入工具 v1.0" << endl;
    cout << "============================================" << endl;
    cout << endl;

    cout << "内置客户端大小: " << (EMBEDDED_CLIENT_SIZE / 1024) << " KB" << endl;
    cout << endl;

    // ==================== 收集配置 ====================
    string api_url;
    int api_port;

    cout << "请输入API服务器配置信息" << endl;
    cout << "--------------------------------------------" << endl;

    // 输入API服务器域名
    while (true) {
        cout << "API服务器域名 [例如: config.server.com]: ";
        string input;
        getline(cin, input);
        input = trim(input);

        if (input.empty()) {
            cout << "✗ 域名不能为空" << endl;
            continue;
        }

        if (validate_domain(input)) {
            api_url = input;
            cout << "✓ 域名格式正确" << endl;
            break;
        } else {
            cout << "✗ 域名格式错误,请重新输入" << endl;
            cout << "  示例: config.server.com 或 api.example.com" << endl;
        }
    }

    // 输入API端口
    while (true) {
        cout << "API端口 [默认: 8080]: ";
        string input;
        getline(cin, input);
        input = trim(input);

        if (input.empty()) {
            api_port = 8080;
            break;
        }

        try {
            api_port = stoi(input);
            if (validate_port(api_port)) {
                cout << "✓ 端口有效" << endl;
                break;
            } else {
                cout << "✗ 端口必须在 1-65535 范围内" << endl;
            }
        } catch (...) {
            cout << "✗ 无效的端口号" << endl;
        }
    }

    cout << endl;
    cout << "============================================" << endl;
    cout << "配置摘要" << endl;
    cout << "============================================" << endl;
    cout << "API服务器域名: " << api_url << endl;
    cout << "API端口:       " << api_port << endl;
    cout << "============================================" << endl;
    cout << endl;

    cout << "API端点将为: http://" << api_url << ":" << api_port << "/api/servers" << endl;
    cout << endl;

    // 确认
    cout << "确认以上配置并生成客户端? (Y/N): ";
    string confirm;
    getline(cin, confirm);
    confirm = trim(confirm);
    transform(confirm.begin(), confirm.end(), confirm.begin(), ::tolower);

    if (confirm != "y" && confirm != "yes") {
        cout << "已取消操作。" << endl;
        system("pause");
        return 0;
    }

    cout << endl;
    cout << "============================================" << endl;
    cout << "开始生成多服务器客户端..." << endl;
    cout << "============================================" << endl;

    // ==================== 生成配置客户端 ====================

    // 构造输出文件名 (使用时间戳以避免文件名冲突和编码问题)
    time_t now = time(NULL);
    stringstream output_name;
    output_name << "DNFProxyClient_MultiServer_" << now << ".exe";
    string exe_name = output_name.str();

    cout << "[1/3] 写入客户端二进制..." << endl;
    cout << "  输出文件: " << exe_name << endl;

    // 写入内置的多服务器客户端二进制
    ofstream output(exe_name, ios::binary);
    if (!output.is_open()) {
        cout << "✗ 错误: 无法创建输出文件: " << exe_name << endl;
        cout << "  可能原因: 权限不足或磁盘空间不足" << endl;
        system("pause");
        return 1;
    }

    output.write((const char*)EMBEDDED_CLIENT_DATA, EMBEDDED_CLIENT_SIZE);
    cout << "✓ 客户端二进制已写入 (" << (EMBEDDED_CLIENT_SIZE / 1024) << " KB)" << endl;

    cout << "[2/3] 追加API配置数据..." << endl;

    // 生成JSON配置 (多服务器版本格式)
    stringstream json;
    json << "[CONFIG_START]";
    json << "{";
    json << "\"config_api_url\":\"" << api_url << "\",";
    json << "\"config_api_port\":" << api_port;
    json << "}";
    json << "[CONFIG_END]";

    string config_data = json.str();
    output.write(config_data.c_str(), config_data.length());
    output.close();

    cout << "✓ 配置已追加 (" << config_data.length() << " 字节)" << endl;

    // 获取最终文件大小
    cout << "[3/3] 验证输出文件..." << endl;
    WIN32_FILE_ATTRIBUTE_DATA file_info;
    if (GetFileAttributesExA(exe_name.c_str(), GetFileExInfoStandard, &file_info)) {
        ULONGLONG file_size = (ULONGLONG(file_info.nFileSizeHigh) << 32) | file_info.nFileSizeLow;
        cout << "✓ 文件已生成: " << exe_name << " (" << (file_size / 1024) << " KB)" << endl;
    } else {
        cout << "✓ 文件已生成: " << exe_name << endl;
    }

    cout << endl;
    cout << "============================================" << endl;
    cout << "✓ 生成成功!" << endl;
    cout << "============================================" << endl;
    cout << "输出文件: " << exe_name << endl;
    cout << endl;
    cout << "此程序已包含API配置,启动时将:" << endl;
    cout << "  1. 从 http://" << api_url << ":" << api_port << "/api/servers 获取服务器列表" << endl;
    cout << "  2. 显示GUI选择窗口供用户选择服务器" << endl;
    cout << "  3. 记住用户上次的选择" << endl;
    cout << endl;
    cout << "使用方法:" << endl;
    cout << "  1. 确保API服务器正常运行" << endl;
    cout << "  2. 右键点击 " << exe_name << endl;
    cout << "  3. 选择 \"以管理员身份运行\"" << endl;
    cout << endl;
    cout << "API返回格式要求:" << endl;
    cout << "  {" << endl;
    cout << "    \"servers\": [" << endl;
    cout << "      {" << endl;
    cout << "        \"id\": 1," << endl;
    cout << "        \"name\": \"服务器名称\"," << endl;
    cout << "        \"game_server_ip\": \"192.168.2.110\"," << endl;
    cout << "        \"tunnel_server_ip\": \"192.168.2.75\"," << endl;
    cout << "        \"tunnel_port\": 33223," << endl;
    cout << "        \"download_url\": \"http://example.com/client.zip\"" << endl;
    cout << "      }" << endl;
    cout << "    ]" << endl;
    cout << "  }" << endl;
    cout << endl;

    system("pause");
    return 0;
}
