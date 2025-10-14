#!/bin/bash
# DNF 隧道服务器 - C++ 一键编译脚本

echo "============================================================"
echo "DNF隧道服务器 - C++版本编译工具"
echo "============================================================"
echo ""

# 切换到脚本所在目录
cd "$(dirname "$0")"

# 检查编译器
echo "[1/3] 检查编译环境..."
if ! command -v g++ &> /dev/null; then
    echo "未找到 g++，正在安装..."

    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian
        apt-get update
        apt-get install -y build-essential
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL
        yum groupinstall -y "Development Tools"
        yum install -y gcc-c++
    else
        echo "错误：无法自动安装编译工具，请手动安装 g++"
        exit 1
    fi

    if ! command -v g++ &> /dev/null; then
        echo "错误：安装 g++ 失败"
        exit 1
    fi
fi

g++ --version | head -1
echo "编译环境正常"
echo ""

# 编译
echo "[2/3] 编译中..."
make static

if [ $? -ne 0 ]; then
    echo ""
    echo "错误：编译失败"
    exit 1
fi
echo ""

# 检查结果
echo "[3/3] 编译完成！"
echo ""

if [ -f "dnf-tunnel-server" ]; then
    FILE_SIZE=$(ls -lh dnf-tunnel-server | awk '{print $5}')

    echo "============================================================"
    echo "编译成功！"
    echo "============================================================"
    echo ""
    echo "可执行文件: dnf-tunnel-server"
    echo "文件大小: $FILE_SIZE"
    echo "编译类型: 静态链接（无依赖）"
    echo ""
    echo "兼容性: 兼容所有 x86_64 Linux 系统"
    echo "  ✓ CentOS 6/7/8/9"
    echo "  ✓ Ubuntu 14.04+"
    echo "  ✓ Debian 7+"
    echo "  ✓ RHEL 6/7/8/9"
    echo "  ✓ 所有主流 Linux 发行版"
    echo ""
    echo "使用说明:"
    echo "• 前台运行: ./dnf-tunnel-server"
    echo "• 后台运行: nohup ./dnf-tunnel-server > server.log 2>&1 &"
    echo "• 查看日志: tail -f server.log"
    echo "• 停止服务: killall dnf-tunnel-server"
    echo ""
    echo "配置文件: 编辑 config.json 修改配置"
    echo "============================================================"
else
    echo "错误：未找到编译产物"
    exit 1
fi
