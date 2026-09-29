#!/usr/bin/env bash
# 单机测试脚本：用 veth pair + network namespace 跑协议栈
#
# 拓扑:
#   主 netns (curl 客户端)                      netns "lab" (web_server)
#   veth0: 10.0.0.1/24  <--------veth对-------->  veth1: 10.0.0.2/24
#   curl http://10.0.0.3/   (10.0.0.3 是 config.h 里"借用"的 IP)
#
# 用法:
#   ./veth_lab.sh start   # 建环境并在前台运行 web_server (Ctrl+C 退出并自动清理)
#   ./veth_lab.sh stop    # 手动清理
set -euo pipefail

NS=lab
V0=veth0
V1=veth1
MAIN_IP=10.0.0.1/24
NS_IP=10.0.0.2/24
FAKE_IP=10.0.0.3   # 必须与 include/config.h 中非 TEST 分支的 NET_IF_IP 一致
BIN=build/web_server

cleanup() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$V0" 2>/dev/null || true
}

start() {
    cleanup
    echo "[+] 创建 netns 与 veth 对..."
    ip netns add "$NS"
    ip link add "$V0" type veth peer name "$V1"
    ip link set "$V1" netns "$NS"

    ip addr add "$MAIN_IP" dev "$V0"
    ip link set "$V0" up
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip addr add "$NS_IP" dev "$V1"
    ip netns exec "$NS" ip link set "$V1" up

    echo "[+] 环境就绪，现在可以从另一终端执行:  curl http://$FAKE_IP/"
    echo "[+] 启动 web_server (前台运行，Ctrl+C 退出并自动清理)..."
    trap cleanup EXIT INT TERM
    exec ip netns exec "$NS" "./$BIN"
}

case "${1:-}" in
    start) start ;;
    stop) cleanup; echo "[-] 已清理" ;;
    *) echo "用法: $0 {start|stop}" >&2; exit 1 ;;
esac
