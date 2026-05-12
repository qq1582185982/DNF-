# DNF Android Client

Android 客户端第一版，使用系统 `VpnService` 接入现有虚拟局域网。

当前版本是 relay-only 客户端：

- 通过 TCP 配置接口执行 `GET_SERVERS`
- 通过 `LEASE_IP` / `RENEW_LEASE` / `RELEASE_LEASE` 管理虚拟 IP
- 通过 Android `VpnService.Builder` 创建系统 VPN
- 通过 UDP Packet Tunnel 与服务器互通 IPv4 包
- 不启用 UDP/TCP 对等直连，避免影响现有节点直连/中转策略

## 构建

本目录是标准 Android Studio 工程。用 Android Studio 打开 `android客户端源码`，同步 Gradle 后构建 `app`。

本机当前没有 Gradle/Android SDK 命令行环境，所以本轮没有生成 APK。

## 运行参数

启动界面需要填写：

- API Host：配置服务地址
- API Port：配置服务端口
- Server Key：节点编号，通常是 `1`
- Client ID：安卓设备的稳定客户端 ID

点“获取节点”可以验证配置服务是否可达。点“启动 VPN”后系统会弹出 VPN 授权。
