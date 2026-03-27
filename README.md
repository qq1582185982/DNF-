# DNF游戏代理 - 服务器端口复用版本

## 📋 版本信息
- **版本**: v4.0 IPv6 + 域名支持版
- **日期**: 2025-10-14
- **状态**: ✅ 已完成并测试通过
- **新增功能**: IPv6双栈支持、域名解析

## 🎯 功能特性

### 核心功能
1. **IPv6双栈支持** - 服务器同时支持IPv4和IPv6客户端连接 🆕
2. **域名解析** - 游戏服务器和隧道服务器均支持域名配置 🆕
3. **多服务器端口复用** - 单个服务器进程支持多个游戏服务器
4. **TCP半关闭修复** - 解决游戏退出卡顿问题
5. **智能日志系统** - 支持DEBUG/INFO/WARN/ERROR四级日志
6. **自动日志目录** - 日志统一存放在`log/`目录
7. **配置注入工具** - 无需硬编码配置的客户端

### 架构优势
```
              ┌──────────────────────────────────┐
              │  DNF隧道服务器 (单进程)          │
              │  tcp_tunnel_server               │
              │  监听端口: 33223, 33224, ...     │
              └──────────────────────────────────┘
                     ↓              ↓
         ┌───────────┴──┐      ┌───┴────────────┐
         │ 游戏服务器1   │      │  游戏服务器2   │
         │ 10.0.0.10    │      │  10.0.0.11    │
         │ 端口: 11011  │      │  端口: 11011  │
         │       7001   │      │        7001   │
         │       10011  │      │        10011  │
         └──────────────┘      └────────────────┘
```

## 📁 目录结构

```
服务器端口复用/
├── README.md                              # 本文档
├── 服务器源码/                             # 服务器端代码
│   ├── tcp_tunnel_server.cpp              # 服务器主程序
│   ├── config.json                        # 服务器配置文件
│   ├── build.sh                           # 编译脚本
│   └── Makefile                           # Makefile构建文件
├── 带配置的客户端源码/                      # 客户端代码和工具
│   ├── tcp_proxy_client_no_config.cpp     # 无硬编码配置客户端
│   ├── build-multi-server-client.ps1      # 多服务器客户端编译脚本
│   ├── build-multi-server-injector.ps1    # 多服务器配置器编译脚本
│   ├── config_injector_multiserver.cpp    # 多服务器配置注入工具源码
│   ├── WinDivert.dll                      # WinDivert运行时
│   ├── WinDivert64.sys                    # WinDivert驱动
│   ├── windivert.h                        # WinDivert头文件
│   └── WinDivert.lib                      # WinDivert库文件
└── *.zip                                  # 历史归档文件
```

## 🚀 快速开始

### 服务器端部署 (Linux)

#### 1. 编译服务器
```bash
cd 服务器源码/
chmod +x build.sh
./build.sh
```

或使用Makefile:
```bash
make
```

#### 2. 配置服务器
编辑 `config.json`:
```json
{
  "servers": [
    {
      "name": "服务器1",
      "listen_port": 33223,
      "game_server_ip": "10.0.0.10",           // 支持IPv4
      "max_connections": 100
    },
    {
      "name": "服务器2",
      "listen_port": 33224,
      "game_server_ip": "2001:db8::10",        // 支持IPv6 🆕
      "max_connections": 100
    },
    {
      "name": "服务器3",
      "listen_port": 33225,
      "game_server_ip": "game.example.com",    // 支持域名 🆕
      "max_connections": 100
    }
  ],
  "log_level": "INFO"
}
```

#### 3. 启动服务器
```bash
# 前台运行（推荐测试时使用）
./dnf-tunnel-server

# 后台运行（生产环境）
nohup ./dnf-tunnel-server > /dev/null 2>&1 &
```

#### 4. 查看日志
```bash
tail -f log/server_log_*.txt
```

### 客户端部署 (Windows)

#### 当前仅保留多服务器客户端构建链路

单服务器客户端版本已移除。

请使用多服务器版：

```powershell
cd 客户端源码/
.\build-multi-server-client.ps1
.\build-multi-server-injector.ps1
```

输出文件：
- `DNF_Proxy_Client_MultiServer_v12.4.0.exe`
- `DNFConfigInjector_MultiServer.exe`

#### 运行客户端
1. **必须以管理员权限运行**（右键→以管理员身份运行）
2. 客户端会自动在 `log/` 目录生成日志文件
3. 配置成功后，客户端会显示：
```
============================================================
DNF游戏代理客户端 v5.0 (C++ 版本 - TCP)
============================================================

已读取配置:
  游戏服务器: 192.168.1.100
  隧道服务器: 10.0.0.50:33223

代理客户端已启动
按Ctrl+C退出...
```

## 🌐 IPv6 和域名支持 (v4.0新增)

### IPv6 支持

**服务器端**:
- 自动启用IPv6双栈监听（同时接受IPv4和IPv6连接）
- 游戏服务器连接支持IPv6地址
- 日志中会显示客户端协议类型（IPv4/IPv6）

**客户端**:
- 自动检测游戏服务器IP类型（IPv4/IPv6）
- WinDivert过滤器自动适配协议
- 支持连接IPv6隧道服务器

**配置示例**:
```json
// 服务器配置
{
  "game_server_ip": "2001:db8::1",      // IPv6地址
  "listen_port": 33223
}

// 客户端配置（通过 DNFConfigInjector_MultiServer.exe 注入）
{
  "config_api_url": "config.example.com",
  "config_api_port": 35000,
  "version_name": "多服务器版"
}
```

### 域名解析

**支持场景**:
- 游戏服务器使用域名（服务器端）
- 隧道服务器使用域名（客户端）
- 自动DNS解析，支持多地址轮询

**配置示例**:
```json
// 服务器配置
{
  "game_server_ip": "game.example.com",  // 域名
  "listen_port": 33223
}

// 客户端配置（通过 DNFConfigInjector_MultiServer.exe 注入）
{
  "config_api_url": "config.example.com",  // 配置接口域名
  "config_api_port": 35000,
  "version_name": "多服务器版"
}
```

**DNS解析特性**:
- 使用 `getaddrinfo()` 实现跨平台DNS解析
- 自动尝试所有解析结果（支持多IP轮询）
- 失败自动切换下一个IP地址
- 支持IPv4和IPv6混合解析

### 混合配置示例

```json
{
  "servers": [
    {
      "name": "本地服务器",
      "listen_port": 33223,
      "game_server_ip": "192.168.1.100",     // IPv4
      "max_connections": 100
    },
    {
      "name": "远程服务器",
      "listen_port": 33224,
      "game_server_ip": "game.example.com",  // 域名
      "max_connections": 100
    },
    {
      "name": "IPv6服务器",
      "listen_port": 33225,
      "game_server_ip": "2001:db8::10",      // IPv6
      "max_connections": 100
    }
  ],
  "log_level": "INFO"
}
```

## 🔧 配置说明

### 服务器配置 (config.json)

```json
{
  "listen_ports": [33223, 33224],           // 隧道监听端口列表
  "log_level": "INFO",                      // 日志级别: DEBUG/INFO/WARN/ERROR
  "servers": [                              // 游戏服务器列表
    {
      "name": "服务器1",                     // 服务器名称（显示在日志中）
      "game_server_ip": "10.0.0.10",        // 游戏服务器IP
      "ports": [11011, 7001, 10011]         // 游戏端口列表
    }
  ]
}
```

### 客户端配置

客户端当前统一通过多服务器配置器注入 API 配置：
- **config_api_url**: 配置接口地址
- **config_api_port**: 配置接口端口
- **version_name**: 客户端显示版本名

## 📊 日志系统

### 日志级别说明

| 级别  | 用途                                           | 示例                                  |
|-------|------------------------------------------------|---------------------------------------|
| DEBUG | 详细调试信息（包序列号、hex dump等）           | TCP包详情、窗口大小、ACK确认          |
| INFO  | 关键业务事件                                   | 连接建立、连接断开、启动/停止          |
| WARN  | 警告信息（不影响运行）                         | 窗口阻塞、缓冲区过大                   |
| ERROR | 错误信息（影响运行）                           | 连接失败、socket错误                   |

### INFO级别日志示例（默认）

**服务器端**:
```
2025-10-14 12:00:00.001 [INFO] 服务器配置加载完成
2025-10-14 12:00:00.002 [INFO] 监听端口: 33223, 33224
2025-10-14 12:00:00.003 [INFO] 服务器已启动，等待连接...
2025-10-14 12:00:10.123 [INFO] [连接1] 新客户端连接 127.0.0.1:45678 -> 端口10011
2025-10-14 12:00:10.125 [INFO] [连接1] ✓ 连接到游戏服务器 10.0.0.10:10011
```

**客户端**:
```
2025-10-14 12:00:10.100 [INFO] 代理客户端已启动
2025-10-14 12:00:10.200 [INFO] [连接1] ✓ TCP连接已建立 (收到ACK=12346)
```

### DEBUG级别日志
包含所有详细信息，用于问题诊断：
```bash
# 修改服务器 config.json
{
  "log_level": "DEBUG"
}

# 客户端需要重新编译或修改源码
```

## 🛠️ 技术细节

### 服务器端口复用实现

**端口到服务器的映射**:
```cpp
// config.json 配置:
"listen_ports": [33223, 33224]
"servers": [
  {"game_server_ip": "10.0.0.10", "ports": [11011, 7001, 10011]},
  {"game_server_ip": "10.0.0.11", "ports": [11011, 7001, 10011]}
]

// 映射关系:
隧道端口33223 → 服务器索引0 → 10.0.0.10
隧道端口33224 → 服务器索引1 → 10.0.0.11
```

**连接流程**:
1. 客户端连接隧道端口（如33223）
2. 发送握手包：`conn_id(4字节) + game_port(2字节)`
3. 服务器根据隧道端口确定游戏服务器IP
4. 服务器连接 `game_server_ip:game_port`
5. 建立双向转发隧道

### TCP半关闭机制

解决游戏退出卡顿问题：

```cpp
// 游戏服务器发送FIN时
if (n == 0) {
    // 只关闭游戏→客户端方向
    shutdown(game_fd, SHUT_RD);
    // 保持客户端→游戏方向开启，允许客户端发送剩余数据
}

// 客户端→游戏转发检测到EPIPE时
if (errno == EPIPE) {
    // 此时才安全关闭整个连接
    running = false;
}
```

### 配置注入原理

客户端配置以JSON格式追加到exe文件末尾：

```
[EXE文件内容]
[CONFIG_START]{"config_api_url":"config.example.com","config_api_port":35000,"version_name":"多服务器版"}[CONFIG_END]
```

客户端启动时：
1. 获取自身exe路径
2. 从文件末尾读取8KB
3. 搜索 `[CONFIG_START]` 和 `[CONFIG_END]` 标记
4. 提取中间的JSON配置
5. 解析并应用配置

## 🐛 故障排查

### 常见问题

**1. 客户端提示"需要管理员权限"**
```
解决方案：右键程序 → 以管理员身份运行
原因：WinDivert需要管理员权限加载驱动
```

**2. 客户端提示"WinDivert打开失败"**
```
错误87：过滤器语法错误
  → 检查游戏服务器IP配置是否正确

其他错误：
  → 确认WinDivert.dll和WinDivert64.sys在同目录
  → 以管理员权限运行
  → 检查杀毒软件是否拦截
```

**3. 服务器日志显示"连接到游戏服务器失败"**
```
检查项：
  ✓ 游戏服务器IP是否正确
  ✓ 游戏端口是否开放
  ✓ 网络连通性：ping game_server_ip
  ✓ 防火墙规则
```

**4. 游戏退出仍然卡顿**
```
检查：
  ✓ 服务器是否使用了TCP半关闭修复版本
  ✓ 查看服务器日志是否有"执行半关闭"字样
  ✓ 检查是否有"发送到游戏服务器失败"错误
```

### 日志分析

**查看连接建立过程**:
```bash
# 服务器端
grep "新客户端连接\|连接到游戏服务器" log/server_log_*.txt

# 客户端
grep "TCP连接已建立" log/client_log_*.txt
```

**查看错误信息**:
```bash
# 服务器端
grep "\[ERROR\]\|\[WARN\]" log/server_log_*.txt

# 客户端
grep "\[ERROR\]\|\[WARN\]" log/client_log_*.txt
```

**分析退出流程**:
```bash
grep "FIN\|半关闭\|断开" log/server_log_*.txt
```

## 📈 性能优化

### 服务器端
- **TCP_NODELAY**: 禁用Nagle算法，降低延迟
- **线程池**: 每个连接使用独立的转发线程对
- **缓冲区**: 4KB接收缓冲区
- **日志刷新**: 每条日志立即刷新，确保数据不丢失

### 客户端
- **WinDivert优先级**: 1000（高优先级）
- **窗口管理**: 根据游戏端口自适应窗口大小
  - 端口10011: 245字节
  - 端口7001: 228字节
  - 其他端口: 229字节
- **窗口探测**: 当游戏窗口为0时，每秒发送探测包

## 🔐 安全建议

1. **生产环境**:
   - 使用防火墙限制隧道端口访问
   - 配置日志级别为INFO或WARN
   - 定期清理日志文件
   - 监控服务器资源使用

2. **日志管理**:
   ```bash
   # 自动清理7天前的日志
   find log/ -name "*.txt" -mtime +7 -delete

   # 日志轮转（可选）
   logrotate /etc/logrotate.d/dnf-tunnel
   ```

3. **进程管理**:
   ```bash
   # 使用systemd管理（推荐）
   sudo systemctl enable dnf-tunnel
   sudo systemctl start dnf-tunnel

   # 或使用supervisor
   ```

## 📝 变更历史

### v4.0 (2025-10-14)
- ✨ **新增：IPv6双栈支持** - 服务器同时支持IPv4/IPv6客户端
- ✨ **新增：域名解析** - 游戏服务器和隧道服务器支持域名配置
- 🔧 改进：使用 `getaddrinfo()` 替代 `inet_pton()` 实现灵活地址解析
- 🔧 改进：WinDivert过滤器自动适配IPv4/IPv6
- 🔧 改进：服务器监听使用 `sockaddr_in6` 双栈模式
- 📝 文档：添加IPv6和域名配置示例
- ⚡ 性能：DNS解析支持多地址自动轮询
- ✅ 兼容：完全向后兼容现有IPv4配置

### v3.3 (2025-10-14)
- ✨ 新增：多服务器端口复用架构
- ✨ 新增：智能日志级别系统（DEBUG/INFO/WARN/ERROR）
- ✨ 新增：自动日志目录（log/）
- ✨ 新增：配置注入工具，无需硬编码
- 🐛 修复：TCP半关闭机制
- 🐛 修复：游戏退出卡顿问题
- 📝 优化：日志输出简洁清晰

### v3.2 (2025-10-13)
- 🐛 修复：TCP半关闭实现
- 📝 新增：详细错误日志

### v3.1 及更早版本
- 见主目录 README.md

## 📚 相关文档

- [主README](../README.md) - TCP半关闭修复详细说明
- [架构文档](../文档/ARCHITECTURE.md) - 系统架构设计
- [测试日志](../测试日志/) - 实际测试日志和分析

## 📞 支持

遇到问题？
1. 查看 [故障排查](#故障排查) 章节
2. 检查日志文件（`log/` 目录）
3. 提交Issue并附带日志文件

## 📜 许可证

本项目仅供学习和研究使用。

---

**最后更新**: 2025-10-14
**版本**: v4.0 IPv6 + 域名支持版
**状态**: ✅ 生产就绪

## 🔍 技术亮点

### IPv6双栈实现
```cpp
// 服务器监听 - IPv6双栈
listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
int v6only = 0;
setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
// 现在可以同时接受IPv4和IPv6连接
```

### 域名解析实现
```cpp
// 使用getaddrinfo支持域名/IPv4/IPv6
struct addrinfo hints{}, *result = nullptr;
hints.ai_family = AF_UNSPEC;      // 允许IPv4或IPv6
hints.ai_socktype = SOCK_STREAM;
getaddrinfo(hostname, port_str, &hints, &result);

// 自动尝试所有解析结果
for (rp = result; rp != nullptr; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
        break;  // 连接成功
    }
}
```

### WinDivert协议自适应
```cpp
// 客户端自动检测IP类型
bool is_ipv6 = (game_server_ip.find(':') != string::npos);
string filter = is_ipv6
    ? "ipv6.DstAddr == " + game_server_ip  // IPv6过滤器
    : "ip.DstAddr == " + game_server_ip;    // IPv4过滤器
```
