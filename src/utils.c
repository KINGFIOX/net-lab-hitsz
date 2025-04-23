#include "utils.h"

#include "buf.h"
#include "ip.h"
#include "net.h"
#include "testing/log.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
/**
 * @brief ip转字符串
 *
 * @param ip ip地址
 * @return char* 生成的字符串
 */
char *iptos(const uint8_t *ip) {
    static char output[3 * 4 + 3 + 1];
    sprintf(output, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return output;
}

/**
 * @brief mac转字符串
 *
 * @param mac mac地址
 * @return char* 生成的字符串
 */
char *mactos(uint8_t *mac) {
    static char output[2 * 6 + 5 + 1];
    sprintf(output, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return output;
}

/**
 * @brief 时间戳转字符串
 *
 * @param timestamp 时间戳
 * @return char* 生成的字符串
 */
char *timetos(time_t timestamp) {
    static char output[20];
    struct tm *utc_time = gmtime(&timestamp);
    sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d", utc_time->tm_year + 1900, utc_time->tm_mon + 1, utc_time->tm_mday, utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec);
    return output;
}

/**
 * @brief ip前缀匹配
 *
 * @param ipa 第一个ip
 * @param ipb 第二个ip
 * @return uint8_t 两个ip相同的前缀长度
 */
uint8_t ip_prefix_match(const uint8_t *ipa, const uint8_t *ipb) {
    uint8_t count = 0;
    for (size_t i = 0; i < 4; i++) {
        uint8_t flag = ipa[i] ^ ipb[i];
        for (size_t j = 0; j < 8; j++) {
            if (flag & (1 << 7))
                return count; // first bit not match
            else
                count++, flag <<= 1;
        }
    }
    return count;
}

/**
 * @brief 计算16位校验和
 *
 * @param buf 要计算的数据包
 * @param size 要计算的长度
 * @return uint16_t 校验和
 */
uint16_t checksum16(uint16_t *data, size_t len) {
    // TO-DO
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
        if (sum > 0x0000ffff) {
            sum = (sum & 0x0000ffff) + (sum >> 16);
        }
    }
    uint16_t checksum = ~sum;
    return checksum;
}

#pragma pack(1)
typedef struct peso_hdr {
    uint8_t src_ip[4];     // 源IP地址
    uint8_t dst_ip[4];     // 目的IP地址
    uint8_t placeholder;   // 必须置0,用于填充对齐
    uint8_t protocol;      // 协议号
    uint16_t total_len16;  // 整个数据包的长度
} peso_hdr_t;
#pragma pack()

/**
 * @brief 计算传输层协议（如TCP/UDP）的校验和
 *
 * @param protocol  传输层协议号（如NET_PROTOCOL_UDP、NET_PROTOCOL_TCP）
 * @param buf       待计算的数据包缓冲区
 * @param src_ip    源IP地址
 * @param dst_ip    目的IP地址
 * @return uint16_t 计算得到的16位校验和
 */
uint16_t transport_checksum(uint8_t protocol, buf_t *buf, const uint8_t *src_ip, const uint8_t *dst_ip) {
    // TO-DO
    // saved the old ip_hdr
    static peso_hdr_t reserved;
#if 0
    putchar('\n');
    printf(BLUE);
    printf("old_ip_hdr:\n");
    for (int i = 0; i < sizeof(ip_hdr_t); i++) {
        printf("%02x ", ((uint8_t *)&old_ip_hdr)[i]);
    }
    putchar('\n');
    printf(RESET);
#endif
    uint16_t udp_len = buf->len;
    buf_add_header(buf, sizeof(peso_hdr_t));
    uint16_t total_len = buf->len;
    peso_hdr_t *peso_hdr = (peso_hdr_t *)buf->data;
    memcpy(&reserved, peso_hdr, sizeof(peso_hdr_t)); // reserved
    memcpy(peso_hdr->src_ip, src_ip, NET_IP_LEN);
    memcpy(peso_hdr->dst_ip, dst_ip, NET_IP_LEN);
    peso_hdr->placeholder = 0;
    peso_hdr->protocol = protocol;
    peso_hdr->total_len16 = htons(udp_len);
    int parity = (total_len % 2 == 1); // buf->len include the peso_hdr_t
    buf_add_padding(buf, parity);
    uint16_t checksum = checksum16((uint16_t *)peso_hdr, ((total_len + parity) >> 1));
    buf_remove_padding(buf, parity);
    buf_remove_header(buf, sizeof(peso_hdr_t));
    memcpy(peso_hdr, &reserved, sizeof(peso_hdr_t));
    return checksum;
}