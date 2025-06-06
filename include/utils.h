#ifndef UTILS_H
#define UTILS_H

#include "buf.h"

#include <stdint.h>
#include <time.h>

uint16_t checksum16(uint16_t *data, size_t len);
uint16_t transport_checksum(uint8_t protocol, buf_t *buf, const uint8_t *src_ip, const uint8_t *dst_ip);

#define swap16(x) ((((x)&0xFF) << 8) | (((x) >> 8) & 0xFF))                                                  // 为16位数据交换大小端
#define swap32(x) ((((x)&0xFF) << 24) | (((x)&0xFF00) << 8) | (((x)&0xFF0000) >> 8) | (((x) >> 24) & 0xFF))  // 为32位数据交换大小端

char *iptos(const uint8_t *ip);
char *mactos(uint8_t *mac);
char *timetos(time_t timestamp);
uint8_t ip_prefix_match(const uint8_t *ipa, const uint8_t *ipb);
#endif