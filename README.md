# HITSZ 计算机网络实验：手写 TCP/IP 协议栈

基于 **libpcap** 的用户态以太网/IP/TCP 协议栈，从零实现 ARP、IP 分片、ICMP、UDP、TCP，并提供一个可被 `curl` 访问的 HTTP Web 服务器。

> 本项目是实验作业。协议栈运行在用户态，通过 libpcap 直接向网卡收发**原始以太网帧**，绕开内核协议栈。

---

## 功能特性

| 层次 | 实现 |
|------|------|
| 以太网 | 帧收发、BPF 过滤、最小帧填充 |
| ARP | 请求/应答、ARP 缓存表、pending 发送队列、GARP |
| IP | 校验和、分片发送、TTL、协议分发 |
| ICMP | Echo 应答、端口/协议不可达 |
| UDP | 端口注册、回调分发 |
| TCP | 三次握手、序列号/确认号、连接状态机、数据收发、FIN 关闭 |
| 应用层 | HTTP Web 服务器（GET、404、静态资源、Keep-Alive） |

---

## 目录结构

```
.
├── app/                  # 应用程序
│   ├── web_server.c      # HTTP 服务器（监听 80 端口）
│   ├── tcp_server.c      # TCP 回显服务器（监听 60000 端口）
│   ├── udp_server.c      # UDP 回显服务器（监听 60000 端口）
│   └── resource/         # web 服务器静态资源
├── include/              # 头文件
│   ├── config.h          # ⭐ 网络配置（IP / MAC）
│   └── *.h               # 各协议头文件
├── src/                  # 协议栈实现
│   ├── driver.c          # libpcap 网卡收发驱动
│   ├── ethernet.c        # 以太网帧处理
│   ├── arp.c             # ARP 协议
│   ├── ip.c              # IP 协议 + 分片
│   ├── icmp.c            # ICMP 协议
│   ├── udp.c             # UDP 协议
│   ├── tcp.c             # TCP 协议
│   ├── map.c / buf.c     # 通用哈希表 / 缓冲区工具
│   └── ...
├── testing/              # 单元测试（配合 faker 驱动）
├── CMakeLists.txt
├── Makefile
└── veth_lab.sh           # ⭐ 单机测试脚本（veth + netns）
```

---

## 依赖

- Linux（root 权限运行，libpcap 需要）
- `gcc` / `cmake` / `make`
- `libpcap-dev`
- （Windows 下使用 Npcap，见 `src/driver.c`）

Ubuntu / Debian 安装依赖：

```bash
sudo apt install build-essential cmake libpcap-dev
```

---

## 构建

```bash
# 方式一：make
make build          # 等价于 cmake -B build -S . && cmake --build build

# 方式二：cmake
cmake -B build -S .
cmake --build build -j$(nproc)
```

构建产物在 `build/` 下：

| 可执行文件 | 说明 |
|-----------|------|
| `web_server` | HTTP 服务器，监听 80 端口 |
| `tcp_server` | TCP 回显，监听 60000 端口 |
| `udp_server` | UDP 回显，监听 60000 端口 |
| `*_test` | 单元测试（`eth_in`、`arp_test`、`ip_test`、`tcp_test` 等） |

---

## 配置网络参数

所有网络参数集中在 `include/config.h`：

```c
#ifdef TEST
#define NET_IF_IP   { 10, 211, 199, 240 }                  // 单元测试用
#define NET_IF_MAC  { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }
#else
#define NET_IF_IP   { 10, 0, 0, 3 }                        // 运行时"借用"的 IP
#define NET_IF_MAC  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } // 运行时"扮演"的 MAC
#endif
```

**必须满足三个条件：**

1. `NET_IF_IP` 与所选网卡**同网段**（`driver_find` 按最长前缀匹配选网卡）；
2. `NET_IF_IP` **没有配置在任何接口上**、局域网内**未被占用**；
3. `NET_IF_MAC` 与真实网卡 MAC **不同**（BPF 过滤器依赖这一点区分"自己的帧"和"内核的帧"）。

> 改完 `config.h` 后需要重新 `make build`。

---

## 运行

### 方式一：单机测试（veth + netns，推荐）

真实网卡/交换机存在一个固有限制：**从本机网卡发出的帧不会回到本机网卡的接收路径**（网卡 TX 不回环 RX，交换机也不回发源端口）。因此"在本机 curl 本机"跑不通。

本项目用 `veth pair + network namespace` 造一根"软件网线"，把客户端和服务端隔成两台逻辑主机，绕开上述限制：

```bash
# 终端 1：创建环境并在前台运行 web_server（Ctrl+C 自动清理）
./veth_lab.sh start

# 终端 2：测试
curl http://10.0.0.3/
curl http://10.0.0.3/404.html
curl -o /tmp/img.jpg http://10.0.0.3/assets/img3.jpg

# 清理
./veth_lab.sh stop
```

拓扑：

```
主 netns                          netns "lab"
curl → 内核 → veth0 (10.0.0.1)  ←—veth 网线—→  veth1 (10.0.0.2)
                                                  ↑ pcap 抓包
                                                  web_server（借用 10.0.0.3）
```

原理：veth 驱动会把一端的 TX 帧**必然投递**到对端 RX，实现了真实网卡/交换机没有的"回环"能力；netns 则把客户端与服务端隔离成两个独立网络栈。

### 方式二：跨机测试（真实拓扑）

从**另一台同网段机器**访问本机：

1. 把 `NET_IF_IP` 改成本机网卡网段内**未占用**的 IP；
2. 重新编译并运行 `./build/web_server`；
3. 在对端机器执行 `curl http://<NET_IF_IP>/`。

> ⚠️ 若运行在 **ESXi / VMware vSwitch** 上，需把端口组安全策略的
> **"Forged Transmits"（伪造传输）** 和 **"MAC Address Changes"** 设为 **Accept**，
> 否则本程序伪造源 MAC 的帧会被虚拟交换机丢弃。

---

## 单元测试

```bash
cd build
ctest
```

测试用例覆盖：以太网收发、ARP、IP（含分片）、ICMP、UDP、TCP。

---

## 已知问题

1. **TCP 收包校验和未生效**：`src/tcp.c` 的 `tcp_in()` 中校验和失败后仅有调试输出，`return; // drop` 被注释掉了，协议栈会"带病运行"。
2. **主循环忙等**：`net_poll()` 非阻塞轮询且无睡眠，运行时会占满一个 CPU 核心。建议在循环中加 `usleep(1000)` 或改用阻塞模式。

---

## 常见问题（FAQ）

**Q：本机 curl 自己的协议栈，为什么报 `No route to host`？**

A：`No route to host` 表示 **ARP 解析失败**。根本原因是：协议栈（用户态 pcap）发出的 ARP 应答，目的 MAC 就是本机网卡自己的 MAC，而"同一网卡发出的帧不会回到同一网卡的接收路径"，交换机也不会从原端口回发。所以内核永远收不到应答，邻居表停在 `FAILED`。请改用**方式一（veth+netns）**或**方式二（跨机）**。

**Q：为什么能抓到内核发的 ARP 请求，却还是不通？**

A：libpcap 的 packet socket 会通过内核 **egress tap** 看到本机发出的出站帧（所以请求能"看到"）；但应答要进入内核的**接收路径**，必须走真实收发，这一步被"网卡不回环 + 交换机不回发"堵死。

**Q：可以把 `NET_IF_IP` 设成 `127.0.0.1` 吗？**

A：不行。loopback 是 L3 伪接口，无 MAC、无 ARP；`127.0.0.1` 还会触发 `driver_find` 的"与网卡同 IP"检查直接失败；即使强行抓 `lo`，帧的源/目的 MAC 全为 0，不满足 BPF 过滤条件。
