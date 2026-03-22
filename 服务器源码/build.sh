#!/bin/bash
set -e

MODE="${1:-musl}"

echo "============================================================"
echo "DNF隧道服务器 - C++版本编译工具"
echo "============================================================"
echo ""

cd "$(dirname "$0")"

echo "[1/3] 检查编译环境..."
if ! command -v g++ >/dev/null 2>&1; then
    echo "错误：未找到 g++"
    exit 1
fi

g++ --version | head -1

if [ "$MODE" = "musl" ]; then
    if command -v x86_64-linux-musl-g++ >/dev/null 2>&1; then
        export MUSL_CXX=x86_64-linux-musl-g++
    elif command -v musl-g++ >/dev/null 2>&1; then
        export MUSL_CXX=musl-g++
    elif command -v zig >/dev/null 2>&1; then
        export MUSL_CXX='zig c++ -target x86_64-linux-musl'
    else
        echo "错误：未找到 musl 工具链"
        echo "可用任一工具：x86_64-linux-musl-g++ / musl-g++ / zig"
        echo "默认发布版现在使用 musl 构建。"
        exit 1
    fi
    sh -lc "$MUSL_CXX --version" | head -1
fi

echo "编译环境正常"
echo ""

echo "[2/3] 编译中..."
case "$MODE" in
    musl)
        echo "编译模式: musl 静态发布版"
        make musl
        ;;
    static)
        echo "编译模式: glibc 静态版"
        make static
        ;;
    dynamic)
        echo "编译模式: 动态链接版"
        make
        ;;
    *)
        echo "错误：未知编译模式: $MODE"
        echo "可选：musl / static / dynamic"
        exit 1
        ;;
esac
echo ""

echo "[3/3] 编译完成！"
echo ""

if [ ! -f "dnf-tunnel-server" ]; then
    echo "错误：未找到编译产物 dnf-tunnel-server"
    exit 1
fi

FILE_SIZE=$(ls -lh dnf-tunnel-server | awk '{print $5}')

echo "============================================================"
echo "编译成功！"
echo "============================================================"
echo ""
echo "可执行文件: dnf-tunnel-server"
echo "文件大小: $FILE_SIZE"

case "$MODE" in
    musl)
        echo "编译类型: musl 静态发布版"
        echo "说明: 默认发布版，优先用于兼容老系统（如 CentOS 6）"
        ;;
    static)
        echo "编译类型: glibc 静态版"
        echo "说明: 兼容性取决于编译机 glibc 和目标内核版本"
        ;;
    dynamic)
        echo "编译类型: 动态链接版"
        echo "说明: 兼容性取决于目标机器 glibc / libstdc++ 版本"
        ;;
esac

echo ""
echo "使用说明:"
echo "• 前台运行: ./dnf-tunnel-server"
echo "• 后台运行: nohup ./dnf-tunnel-server > server.log 2>&1 &"
echo "• 查看日志: tail -f server.log"
echo "• 停止服务: killall dnf-tunnel-server"
echo ""
echo "配置文件: 编辑 config.json 修改配置"
echo "============================================================"
