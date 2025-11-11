/*
 * HTTP API服务器头文件
 */

#ifndef HTTP_API_SERVER_H
#define HTTP_API_SERVER_H

#include <pthread.h>

// 启动HTTP API服务器
// config_file: config.json路径
// tunnel_server_ip: 隧道服务器IP (返回给客户端)
// api_port: API服务器监听端口
// 返回: 服务器线程ID,失败返回0
pthread_t start_http_api_server(const char* config_file, const char* tunnel_server_ip, int api_port);

// 停止HTTP API服务器
void stop_http_api_server();

// 重新加载配置（热重载）
bool reload_http_api_config();

#endif // HTTP_API_SERVER_H
