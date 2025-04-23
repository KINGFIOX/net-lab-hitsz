#include "icmp.h"

#include "buf.h"
#include "ip.h"
#include "net.h"
#include "utils.h"

#include <string.h>

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, const uint8_t *src_ip) {
    // TO-DO
    buf_init(&txbuf, req_buf->len);
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = 0x0;  // echo reply
    icmp_hdr->code = 0x0;
    icmp_hdr->checksum16 = 0;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = ((icmp_hdr_t *)req_buf)->seq16;  // just copy
    icmp_hdr->id16 = ((icmp_hdr_t *)req_buf)->id16;
    memcpy(icmp_hdr + 1, ((icmp_hdr_t *)req_buf) + 1, req_buf->len - sizeof(icmp_hdr_t));
    icmp_hdr->checksum16 = checksum16(icmp_hdr, req_buf->len);
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, const uint8_t *src_ip) {
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;
    if (buf->len < sizeof(icmp_hdr_t)) {
        return;  // drop, non integrity
    }
    uint16_t type_code = (icmp_hdr->type << 8) | (icmp_hdr->code);
    switch (type_code) {
        case 0x80:  // echo request
            icmp_resp(buf, src_ip);
            break;
        default:
            break;
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    buf_init(&txbuf, recv_buf->len);
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = 0x3;  // 协议不可达, 端口不可达
    icmp_hdr->code = code;
    icmp_hdr->checksum16 = 0;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;
    memcpy(icmp_hdr + 1, recv_buf, sizeof(ip_hdr_t) + 8);
    icmp_hdr->checksum16 = checksum16(icmp_hdr, sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8);
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}