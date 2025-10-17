/*
 * DNF代理客户端 - 配置注入工具 v2.0
 * 内置客户端二进制，追加配置生成最终exe
 * 支持IPv4、IPv6地址和域名
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <algorithm>

#include "embedded_client.h"  // 内置客户端二进制

using namespace std;

// ==================== 工具函数 ====================

// 验证地址格式（支持IPv4、IPv6、域名）
bool validate_address(const string& addr) {
    if (addr.empty()) {
        return false;
    }

    // IPv4格式检测
    regex ipv4_pattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    if (regex_match(addr, ipv4_pattern)) {
        int a, b, c, d;
        if (sscanf(addr.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            if (a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
                c >= 0 && c <= 255 && d >= 0 && d <= 255) {
                return true;  // 有效的IPv4地址
            }
        }
        return false;
    }

    // IPv6格式检测（简单检测，包含冒号）
    if (addr.find(':') != string::npos) {
        // 基本IPv6格式检查：包含至少2个冒号，只包含十六进制字符和冒号
        regex ipv6_pattern("^[0-9a-fA-F:]+$");
        if (regex_match(addr, ipv6_pattern)) {
            int colon_count = count(addr.begin(), addr.end(), ':');
            if (colon_count >= 2 && colon_count <= 7) {
                return true;  // 有效的IPv6地址
            }
        }
        return false;
    }

    // 域名格式检测
    // 允许字母、数字、连字符、点号，必须包含至少一个点号
    regex domain_pattern("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");
    if (regex_match(addr, domain_pattern) && addr.find('.') != string::npos) {
        return true;  // 有效的域名
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

// 将地址转换为安全的文件名格式
string sanitize_for_filename(const string& addr) {
    string safe = addr;
    // 替换所有非法文件名字符为下划线
    // Windows不允许: < > : " / \ | ? *
    const string illegal_chars = "<>:\"/\\|?*";
    for (char c : illegal_chars) {
        replace(safe.begin(), safe.end(), c, '_');
    }
    // 限制长度（Windows路径限制）
    if (safe.length() > 50) {
        safe = safe.substr(0, 50);
    }
    return safe;
}

// ==================== 主程序 ====================

int main() {
    // 设置控制台UTF-8编码
    SetConsoleOutputCP(CP_UTF8);
    system("chcp 65001 > nul");

    cout << "========================================" << endl;
    cout << "DNF代理客户端 - 配置注入工具 v2.0" << endl;
    cout << "支持IPv4、IPv6和域名" << endl;
    cout << "========================================" << endl;
    cout << endl;

    cout << "内置客户端大小: " << (EMBEDDED_CLIENT_SIZE / 1024) << " KB" << endl;
    cout << endl;

    // ==================== 收集配置 ====================
    string game_ip, tunnel_ip, version_name;
    int tunnel_port;

    cout << "请输入配置信息（直接回车使用默认值）" << endl;
    cout << "----------------------------------------" << endl;

    // 输入游戏服务器IP/域名
    while (true) {
        cout << "游戏服务器地址 [默认: 192.168.2.110]: ";
        string input;
        getline(cin, input);
        input = trim(input);

        if (input.empty()) {
            game_ip = "192.168.2.110";
            break;
        }

        if (validate_address(input)) {
            game_ip = input;
            // 检测地址类型
            if (input.find(':') != string::npos && input.find('.') == string::npos) {
                cout << "✓ 检测到IPv6地址" << endl;
            } else if (input.find('.') != string::npos &&
                       count(input.begin(), input.end(), '.') == 3) {
                cout << "✓ 检测到IPv4地址" << endl;
            } else {
                cout << "✓ 检测到域名" << endl;
            }
            break;
        } else {
            cout << "✗ 地址格式错误，请重新输入" << endl;
            cout << "  支持格式: IPv4 (192.168.1.100)、IPv6 (2001:db8::1)、域名 (game.example.com)" << endl;
        }
    }

    // 输入隧道服务器IP/域名
    while (true) {
        cout << "隧道服务器地址 [默认: 192.168.2.75]: ";
        string input;
        getline(cin, input);
        input = trim(input);

        if (input.empty()) {
            tunnel_ip = "192.168.2.75";
            break;
        }

        if (validate_address(input)) {
            tunnel_ip = input;
            // 检测地址类型
            if (input.find(':') != string::npos && input.find('.') == string::npos) {
                cout << "✓ 检测到IPv6地址" << endl;
            } else if (input.find('.') != string::npos &&
                       count(input.begin(), input.end(), '.') == 3) {
                cout << "✓ 检测到IPv4地址" << endl;
            } else {
                cout << "✓ 检测到域名" << endl;
            }
            break;
        } else {
            cout << "✗ 地址格式错误，请重新输入" << endl;
            cout << "  支持格式: IPv4 (10.0.0.50)、IPv6 (2001:db8::2)、域名 (tunnel.example.com)" << endl;
        }
    }

    // 输入隧道端口
    while (true) {
        cout << "隧道端口 [默认: 33223]: ";
        string input;
        getline(cin, input);
        input = trim(input);

        if (input.empty()) {
            tunnel_port = 33223;
            break;
        }

        try {
            tunnel_port = stoi(input);
            if (validate_port(tunnel_port)) {
                cout << "OK 端口有效" << endl;
                break;
            } else {
                cout << "X 端口必须在 1-65535 范围内" << endl;
            }
        } catch (...) {
            cout << "X 无效的端口号" << endl;
        }
    }

    // 输入版本名称
    cout << "版本名称 [默认: 未命名版本]: ";
    string name_input;
    getline(cin, name_input);
    name_input = trim(name_input);

    if (name_input.empty()) {
        version_name = "未命名版本";
    } else {
        version_name = name_input;
    }

    cout << endl;
    cout << "========================================" << endl;
    cout << "配置摘要" << endl;
    cout << "========================================" << endl;
    cout << "游戏服务器地址:   " << game_ip << endl;
    cout << "隧道服务器地址:   " << tunnel_ip << endl;
    cout << "隧道端口:         " << tunnel_port << endl;
    cout << "版本名称:         " << version_name << endl;
    cout << "========================================" << endl;
    cout << endl;

    // 确认
    cout << "确认以上配置并生成客户端？(Y/N): ";
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
    cout << "========================================" << endl;
    cout << "开始生成配置客户端..." << endl;
    cout << "========================================" << endl;

    // ==================== 生成配置客户端 ====================

    // 构造输出文件名（处理IPv4、IPv6、域名）
    string game_ip_safe = sanitize_for_filename(game_ip);
    string tunnel_ip_safe = sanitize_for_filename(tunnel_ip);

    stringstream output_name;
    output_name << "DNFProxyClient_" << game_ip_safe << "_" << tunnel_ip_safe << "_" << tunnel_port << ".exe";
    string exe_name = output_name.str();

    cout << "[1/3] 写入客户端二进制..." << endl;

    // 写入内置的客户端二进制
    ofstream output(exe_name, ios::binary);
    if (!output.is_open()) {
        cout << "X 错误: 无法创建输出文件" << endl;
        system("pause");
        return 1;
    }

    output.write((const char*)EMBEDDED_CLIENT_DATA, EMBEDDED_CLIENT_SIZE);
    cout << "OK 客户端二进制已写入 (" << (EMBEDDED_CLIENT_SIZE / 1024) << " KB)" << endl;

    cout << "[2/3] 追加配置数据..." << endl;

    // 生成JSON配置
    stringstream json;
    json << "[CONFIG_START]";
    json << "{";
    json << "\"game_server_ip\":\"" << game_ip << "\",";
    json << "\"tunnel_server_ip\":\"" << tunnel_ip << "\",";
    json << "\"tunnel_port\":" << tunnel_port << ",";
    json << "\"version_name\":\"" << version_name << "\"";
    json << "}";
    json << "[CONFIG_END]";

    string config_data = json.str();
    output.write(config_data.c_str(), config_data.length());
    output.close();

    cout << "OK 配置已追加 (" << config_data.length() << " 字节)" << endl;

    // 获取最终文件大小
    cout << "[3/3] 验证输出文件..." << endl;
    WIN32_FILE_ATTRIBUTE_DATA file_info;
    if (GetFileAttributesExA(exe_name.c_str(), GetFileExInfoStandard, &file_info)) {
        ULONGLONG file_size = (ULONGLONG(file_info.nFileSizeHigh) << 32) | file_info.nFileSizeLow;
        cout << "OK 文件已生成: " << exe_name << " (" << (file_size / 1024) << " KB)" << endl;
    } else {
        cout << "OK 文件已生成: " << exe_name << endl;
    }

    cout << endl;
    cout << "========================================" << endl;
    cout << "生成成功！" << endl;
    cout << "========================================" << endl;
    cout << "输出文件: " << exe_name << endl;
    cout << endl;
    cout << "此程序已包含您的配置，可直接使用:" << endl;
    cout << "  游戏服务器: " << game_ip << endl;
    cout << "  隧道服务器: " << tunnel_ip << ":" << tunnel_port << endl;
    cout << endl;
    cout << "使用方法:" << endl;
    cout << "  1. 右键点击 " << exe_name << endl;
    cout << "  2. 选择 \"以管理员身份运行\"" << endl;
    cout << endl;

    system("pause");
    return 0;
}
