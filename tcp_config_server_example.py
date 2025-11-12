#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP配置服务器示例 - 用于返回服务器列表
替代HTTP API，绕过备案限制

运行方法:
python tcp_config_server_example.py

监听端口: 35000
协议: 接收 "GET_SERVERS\n"，返回JSON格式的服务器列表
"""

import socket
import json
import threading

# 服务器配置
HOST = '0.0.0.0'  # 监听所有网卡
PORT = 35000       # 监听端口

# 服务器列表配置 (根据您的实际情况修改)
SERVER_LIST = {
    "servers": [
        {
            "id": 1,
            "name": "ACT5进化之光",
            "game_server_ip": "192.168.2.110",
            "tunnel_server_ip": "192.168.2.75",
            "tunnel_port": 33223,
            "download_url": "http://192.168.2.22:5244/d/DOF/服务器/ACT5/ACT5客户端.7z"
        },
        {
            "id": 2,
            "name": "70S1",
            "game_server_ip": "192.168.2.110",
            "tunnel_server_ip": "192.168.2.75",
            "tunnel_port": 33224,
            "download_url": "http://192.168.2.22:5244/d/DOF/服务器/70S1/70S1客户端.7z"
        },
        {
            "id": 3,
            "name": "86鱼尾",
            "game_server_ip": "192.168.2.110",
            "tunnel_server_ip": "192.168.2.75",
            "tunnel_port": 33225,
            "download_url": "http://192.168.2.22:5244/d/DOF/服务器/86/86客户端.7z"
        },
        {
            "id": 4,
            "name": "86崔殷",
            "game_server_ip": "192.168.2.110",
            "tunnel_server_ip": "192.168.2.75",
            "tunnel_port": 33226,
            "download_url": "http://192.168.2.22:5244/d/DOF/服务器/86/86客户端.7z"
        }
    ]
}


def handle_client(client_socket, addr):
    """处理客户端连接"""
    try:
        print(f"[新连接] {addr[0]}:{addr[1]}")

        # 接收请求 (最多1024字节)
        request = client_socket.recv(1024).decode('utf-8').strip()
        print(f"[请求] {addr[0]}:{addr[1]} - {repr(request)}")

        if request == "GET_SERVERS":
            # 返回JSON格式的服务器列表
            response = json.dumps(SERVER_LIST, ensure_ascii=False)
            client_socket.sendall(response.encode('utf-8'))
            print(f"[响应] {addr[0]}:{addr[1]} - 已发送服务器列表 ({len(response)} 字节)")
        else:
            # 未知请求
            error_response = json.dumps({"error": "Unknown request"})
            client_socket.sendall(error_response.encode('utf-8'))
            print(f"[警告] {addr[0]}:{addr[1]} - 未知请求: {repr(request)}")

    except Exception as e:
        print(f"[错误] {addr[0]}:{addr[1]} - {e}")
    finally:
        client_socket.close()
        print(f"[断开] {addr[0]}:{addr[1]}")


def main():
    """主函数 - 启动TCP服务器"""
    # 创建TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # 绑定端口
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)

        print("=" * 60)
        print("TCP配置服务器已启动")
        print("=" * 60)
        print(f"监听地址: {HOST}:{PORT}")
        print(f"协议: 接收 'GET_SERVERS', 返回JSON")
        print(f"服务器数量: {len(SERVER_LIST['servers'])}")
        print("=" * 60)
        print()

        # 循环接受连接
        while True:
            try:
                client_socket, addr = server_socket.accept()

                # 为每个客户端创建新线程处理
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()

            except KeyboardInterrupt:
                print("\n[退出] 服务器关闭")
                break
            except Exception as e:
                print(f"[错误] 接受连接失败: {e}")

    except Exception as e:
        print(f"[错误] 无法启动服务器: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
