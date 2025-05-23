#include "net.h"

#include "arp.h"
#include "driver.h"
#include "ethernet.h"
#include "icmp.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"

/**
 * @brief 协议表 <协议号,处理程序>的容器
 *
 */
map_t net_table;

/**
 * @brief 网卡MAC地址
 *
 */
const uint8_t net_if_mac[NET_MAC_LEN] = NET_IF_MAC;

/**
 * @brief 网卡IP地址
 *
 */
const uint8_t net_if_ip[NET_IP_LEN] = NET_IF_IP;

/**
 * @brief 网卡接收和发送缓冲区
 *
 */
buf_t rxbuf, txbuf;  // 一个buf足够单线程使用

/**
 * @brief 初始化协议栈
 *
 */
int net_init() {
    map_init(&net_table, sizeof(uint16_t),
        sizeof(net_handler_t), 0,
        0, NULL, NULL);
    if (driver_open() == -1)
        return -1;
    ethernet_init();
    arp_init();
    ip_init();
#ifdef ICMP
    icmp_init();
#endif
#ifdef UDP
    udp_init();
#endif
#ifdef TCP
    tcp_init();
#endif
    return 0;
}

/**
 * @brief 向协议栈注册一个协议
 *
 * @param protocol 协议号
 * @param handler 该协议的in处理程序
 */
void net_add_protocol(uint16_t protocol, net_handler_t handler) {
    map_set(&net_table, &protocol, &handler);
}

/**
 * @brief 向协议栈的上层协议传递数据包
 *
 * @param buf 要传递的数据包
 * @param protocol 上层协议号
 * @param src 源的本层协议地址，如mac或ip地址
 * @return int 成功为0，失败为-1
 */
int net_in(buf_t *buf, uint16_t protocol, uint8_t *src) {
    net_handler_t *handler = map_get(&net_table, &protocol);
    if (handler) {
        (*handler)(buf, src);
        return 0;
    }
    return -1;
}

/**
 * @brief 一次协议栈轮询
 *
 */
void net_poll() {
    ethernet_poll();
}