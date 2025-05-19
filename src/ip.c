#include "ip.h"

#include "arp.h"
#include "buf.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"
#include "utils.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, const uint8_t *src_mac) {
    // TO-DO
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    uint16_t ip_hdr_len = ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE;
    uint16_t total_len = ntohs(ip_hdr->total_len16);
    if (total_len < ip_hdr_len) {
        return;  // drop, packet shorter than header
    }
    if (ip_hdr->version != IP_VERSION_4) {
        return;  // drop
    }
    if (buf->len < total_len) {
        return;  // drop, buffer shorter than packet length
    }
    // check checksum
    uint16_t checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    if (checksum16((uint16_t *)ip_hdr, ip_hdr_len) != checksum) {
        return;  // drop, checksum error
    }
    ip_hdr->hdr_checksum16 = checksum;
    // check destination ip
    if (memcmp(ip_hdr->dst_ip, net_if_ip, 4) != 0) {
        return;  // drop, packet not for me
    }
    // remove padding
    int pad_len = buf->len - total_len;
    if (pad_len > 0) {
        buf_remove_padding(buf, pad_len);
    }
    buf_remove_header(buf, ip_hdr_len);
    // call protocol handler
    uint8_t protocol = ip_hdr->protocol;
    int ret = net_in(buf, protocol, ip_hdr->src_ip);
    if (ret == -1) {
        buf_add_header(buf, ip_hdr_len);  // restore header
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, const uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = htons(buf->len);
    ip_hdr->id16 = htons(id);
    ip_hdr->flags_fragment16 = htons((offset >> 3) | (mf ? IP_MORE_FRAGMENT : 0));  // FIXME
    ip_hdr->ttl = 64;
    ip_hdr->protocol = protocol;
    memcpy(ip_hdr->src_ip, net_if_ip, 4);
    memcpy(ip_hdr->dst_ip, ip, 4);
    ip_hdr->hdr_checksum16 = 0;
    int checksum = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    ip_hdr->hdr_checksum16 = checksum;
#ifdef MINE
    extern uint8_t dst_mac[];
    ethernet_out(buf, dst_mac, NET_PROTOCOL_IP);
#else
    arp_out(buf, ip);
#endif
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, const uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    static int id = 0;
#ifndef IP_FRAG_TEST
    id = random();
#endif
    // id++;            // counter for ip id
    int offset = 0;  // accumulate offset
    int buf_len = buf->len;
    for (; buf_len > IP_MAX_PAYLOAD; buf_len -= IP_MAX_PAYLOAD, offset += IP_MAX_PAYLOAD) {
        static buf_t frag_buf;
        buf_init(&frag_buf, IP_MAX_PAYLOAD);
        memcpy(frag_buf.data, buf->data + offset, IP_MAX_PAYLOAD);
        ip_fragment_out(&frag_buf, ip, protocol, id, offset, 1);
    }
    buf_remove_header(buf, offset);
    ip_fragment_out(buf, ip, protocol, id, offset, 0);
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}