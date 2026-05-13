# DNF Android Client

Android 客户端使用系统 `VpnService` 接入现有虚拟局域网。
当前版本向 Windows 客户端的直连策略靠拢：智能直连模式下会同时参与 UDP 和 TCP 对等直连，直连不可用时自动回退服务端中转。

- 通过 TCP 配置接口执行 `GET_SERVERS`
- 通过 `LEASE_IP` / `RENEW_LEASE` / `RELEASE_LEASE` 管理虚拟 IP
- 通过 Android `VpnService.Builder` 创建系统 VPN
- 通过 UDP Packet Tunnel 与服务端交换 IPv4 包和对等端控制帧
- 像 Windows 客户端一样额外建立 TCP 中转载体，用于 TCP 中转和 TCP 直连 offer
- 智能直连模式会上报本机 UDP/TCP 候选地址，并处理服务端下发的 UDP/TCP peer offer
- 仅中转模式会在握手时声明 relay-only，虚拟网络包全部走服务端中转

## 构建

本目录是标准 Android Studio 工程。用 Android Studio 打开 `android客户端源码`，同步 Gradle 后构建 `app`。
本机如果没有 Gradle/Android SDK 命令行环境，可以直接使用 GitHub Actions 自动构建。

## 生成带配置客户端

Android 不能像 Windows EXE 一样在二进制末尾追加配置；APK 修改后会破坏签名。安卓版本使用构建期内置配置，配置文件在：

```text
app/src/main/assets/dnf_android_config.json
```

可用脚本生成：

```powershell
.\生成带配置安卓客户端.ps1 -ApiHost cd.sviplk.com -ApiPort 6350 -ServerKey 1
```

如果本机已安装 Android SDK/Gradle，可直接构建：

```powershell
.\生成带配置安卓客户端.ps1 -ApiHost cd.sviplk.com -ApiPort 6350 -ServerKey 1 -Build
```

## GitHub Actions 自动构建

仓库的 `build` 工作流会自动构建安卓 debug APK。先在 GitHub 仓库里进入 `Settings` -> `Secrets and variables` -> `Actions`，添加这些必填 Repository secrets：

```text
ANDROID_CONFIG_API_HOST=cd.sviplk.com
ANDROID_CONFIG_API_PORT=6350
```

可选 secrets：

```text
ANDROID_SERVER_KEY=1
ANDROID_CLIENT_ID=android-phone-001
```

`ANDROID_SERVER_KEY` 不建时默认 `1`；`ANDROID_CLIENT_ID` 不建时安卓端会自动生成设备 ID。GitHub 不支持创建空 secret，所以不需要创建空的 `ANDROID_CLIENT_ID`。推送代码或手动运行 Actions 后，在构建产物里下载 `dnf-android-client-debug-<run_number>`。

## 运行方式

带配置 APK 启动后不会显示配置服务器地址和端口。客户端会自动读取内置配置、拉取节点列表，并显示服务器选择按钮。
点击服务器按钮后再点“连接服务器”，界面会切换到连接日志页；首次连接时系统会弹出 VPN 授权。`Client ID` 默认由安卓设备 ID 自动生成。

服务器选择页提供“数据模式”切换：

- `智能直连`：允许安卓端参与 UDP/TCP 对等直连协商。UDP 包优先走 UDP 直连，TCP 包优先走 TCP 直连；TCP 直连未就绪时优先走 TCP 中转载体，失败再回退 UDP 中转。
- `仅中转`：握手时声明 relay-only，所有虚拟网络包都走服务端中转。
