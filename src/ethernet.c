#include "ethernet.h"

#include "arp.h"
#include "buf.h"
#include "config.h"
#include "driver.h"
#include "ip.h"
#include "net.h"
#include "utils.h"

#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    uint8_t *ptr = buf->data;
    ptr += 6;
    uint8_t src_mac[6];
    memcpy(src_mac, ptr, 6);
    ptr += 6;
    uint16_t protocol = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    buf_remove_header(buf, 14);
    net_in(buf, protocol, src_mac);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    if (buf->len < 46) {
        int pad_len = 46 - buf->len;
        buf_add_padding(buf, pad_len);
    }
    buf_add_header(buf, 14);
    const uint8_t mine[6] = NET_IF_MAC;
    uint8_t *ptr = buf->data;
    memcpy(ptr, mac, 6);
    ptr += 6;
    memcpy(ptr, mine, 6);
    ptr += 6;
    uint16_t protocol_num = htons(protocol);
    memcpy(ptr, &protocol_num, 2);
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
