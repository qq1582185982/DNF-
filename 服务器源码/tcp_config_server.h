/*
 * TCP配置服务器头文件
 * 使用纯TCP协议替代HTTP，绕过备案限制
 */

#ifndef TCP_CONFIG_SERVER_H
#define TCP_CONFIG_SERVER_H

#include <string>
#include <pthread.h>

#include "ip_pool_manager.h"

// 启动TCP配置服务器
// config_file: config.json路径
// tunnel_server_ip: 隧道服务器IP (返回给客户端)
// api_port: TCP服务器监听端口
// 返回: 服务器线程ID,失败返回0
pthread_t start_tcp_config_server(const char* config_file, const char* tunnel_server_ip, int api_port);

// 停止TCP配置服务器
void stop_tcp_config_server();

// 重新加载配置（热重载）
bool reload_tcp_config();
bool query_active_tcp_config_lease(const std::string& server_key,
                                   const std::string& session_uuid,
                                   IPPoolManager::LeaseRecord* out_record,
                                   std::string* error);

#endif // TCP_CONFIG_SERVER_H
