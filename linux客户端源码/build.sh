#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "DNF Linux Tunnel Client Build"
echo "============================================"
make clean
make -j"$(nproc)"
echo
echo "Done: ./dnf-linux-client"