/*
 * 配置缓存管理模块实现
 */

#include "config_manager.h"
#include <shlobj.h>
#include <fstream>

#pragma comment(lib, "shell32.lib")

ConfigManager::ConfigManager() {
    // 获取配置目录路径: %APPDATA%/DNFProxy/
    std::wstring appdata = GetAppDataPath();
    config_dir = appdata + L"\\DNFProxy";
    config_file = config_dir + L"\\last_server.ini";
}

ConfigManager::~ConfigManager() {
}

std::wstring ConfigManager::GetAppDataPath() {
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        return std::wstring(path);
    }
    return L"";
}

bool ConfigManager::EnsureConfigDir() {
    // 检查目录是否存在
    DWORD attr = GetFileAttributesW(config_dir.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        return true;  // 目录已存在
    }

    // 创建目录
    if (CreateDirectoryW(config_dir.c_str(), NULL)) {
        return true;
    }

    // 如果失败，检查是否是因为目录已存在
    DWORD error = GetLastError();
    if (error == ERROR_ALREADY_EXISTS) {
        return true;
    }

    return false;
}

bool ConfigManager::SaveLastServer(int server_id) {
    // 确保配置目录存在
    if (!EnsureConfigDir()) {
        return false;
    }

    // 写入INI文件
    wchar_t value[32];
    swprintf(value, 32, L"%d", server_id);

    BOOL result = WritePrivateProfileStringW(
        L"DNFProxy",       // section
        L"LastServerID",   // key
        value,             // value
        config_file.c_str()
    );

    return (result == TRUE);
}

int ConfigManager::LoadLastServer() {
    // 检查配置文件是否存在
    DWORD attr = GetFileAttributesW(config_file.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return 0;  // 文件不存在，返回0
    }

    // 从INI文件读取
    int server_id = GetPrivateProfileIntW(
        L"DNFProxy",       // section
        L"LastServerID",   // key
        0,                 // default value
        config_file.c_str()
    );

    return server_id;
}
