#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-musl}"

echo "============================================"
echo "DNF Linux Tunnel Client Build"
echo "============================================"

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
        exit 1
    fi
fi

make clean
echo

case "$MODE" in
    musl)
        echo "[1/2] musl static build (default release build)"
        make musl -j"$(nproc)"
        ;;
    static)
        echo "[1/2] glibc static build"
        make static -j"$(nproc)"
        ;;
    dynamic)
        echo "[1/2] dynamic build"
        make dynamic -j"$(nproc)"
        ;;
    *)
        echo "错误：未知编译模式: $MODE"
        echo "可选：musl / static / dynamic"
        exit 1
        ;;
esac

echo
echo "[2/2] Build complete"
echo
echo "Done: ./dnf-linux-client"
