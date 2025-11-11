/*
 * 配置缓存管理模块
 * 保存和读取用户上次选择的服务器
 */

#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <windows.h>

// 配置管理器类
class ConfigManager {
public:
    ConfigManager();
    ~ConfigManager();

    // 保存上次选择的服务器ID
    // server_id: 服务器ID
    // 返回: 是否保存成功
    bool SaveLastServer(int server_id);

    // 读取上次选择的服务器ID
    // 返回: 服务器ID（如果没有记录则返回0）
    int LoadLastServer();

private:
    std::wstring config_dir;    // 配置目录路径
    std::wstring config_file;   // 配置文件路径

    // 确保配置目录存在
    bool EnsureConfigDir();

    // 获取%APPDATA%路径
    std::wstring GetAppDataPath();
};

#endif // CONFIG_MANAGER_H
