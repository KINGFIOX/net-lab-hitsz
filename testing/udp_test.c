#include "driver.h"
#include "ethernet.h"
#include "udp.h"
#include "testing/log.h"

#include <string.h>

extern FILE *pcap_in;
extern FILE *pcap_out;
extern FILE *pcap_demo;
extern FILE *control_flow;
extern FILE *icmp_fout;
extern FILE *tcp_fout;
extern FILE *demo_log;
extern FILE *out_log;
extern FILE *arp_log_f;

char *print_ip(uint8_t *ip);
char *print_mac(uint8_t *mac);

uint8_t my_mac[] = NET_IF_MAC;
uint8_t boardcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int check_log();
int check_pcap();
FILE *open_file(char *path, char *name, char *mode);

void log_tab_buf();

void udp_handler(uint8_t *data, size_t len, const uint8_t *src_ip, uint16_t src_port) {
    printf("recv udp packet from %s:%u len=%zu\n", iptos(src_ip), src_port, len);
    for (int i = 0; i < len; i++)
        putchar(data[i]);
    putchar('\n');
    udp_send(data, len, 60000, src_ip, src_port);  // 发送udp包
}

buf_t buf;
int main(int argc, char *argv[]) {
    int ret;
    PRINT_INFO("Test begin.\n");
    pcap_in = open_file(argv[1], "in.pcap", "r");
    pcap_out = open_file(argv[1], "out.pcap", "w");
    control_flow = open_file(argv[1], "log", "w");
    if (pcap_in == 0 || pcap_out == 0 || control_flow == 0) {
        if (pcap_in)
            fclose(pcap_in);
        else
            PRINT_ERROR("Failed to open in.pcap\n");
        if (pcap_out)
            fclose(pcap_out);
        else
            PRINT_ERROR("Failed to open out.pcap\n");
        if (control_flow)
            fclose(control_flow);
        else
            PRINT_ERROR("Failed to open log\n");
        return -1;
    }
    icmp_fout = control_flow;
    tcp_fout = control_flow;
    arp_log_f = control_flow;

    net_init();
    udp_open(60000, udp_handler);  // 注册端口的udp监听回调
    log_tab_buf();
    int i = 1;
    PRINT_INFO("Feeding input %02d", i);
    while ((ret = driver_recv(&buf)) > 0) {
        printf("\b\b%02d", i);
        fprintf(control_flow, "\nRound %02d -----------------------------\n", i++);
        ethernet_in(&buf);
        log_tab_buf();
    }
    if (ret < 0) {
        PRINT_WARN("\nError occur on loading input,exiting\n");
    }
    driver_close();
    PRINT_INFO("\nSample input all processed, checking output\n");

    fclose(control_flow);

    demo_log = open_file(argv[1], "demo_log", "r");
    out_log = open_file(argv[1], "log", "r");
    pcap_out = open_file(argv[1], "out.pcap", "r");
    pcap_demo = open_file(argv[1], "demo_out.pcap", "r");
    if (demo_log == 0 || out_log == 0 || pcap_out == 0 || pcap_demo == 0) {
        if (demo_log)
            fclose(demo_log);
        else
            PRINT_ERROR("Failed to open demo_log\n");
        if (out_log)
            fclose(out_log);
        else
            PRINT_ERROR("Failed to open log\n");
        if (pcap_demo)
            fclose(pcap_demo);
        else
            PRINT_ERROR("Failed to open demo_out.pcap\n");
        if (pcap_out)
            fclose(pcap_out);
        else
            PRINT_ERROR("Failed to open out.pcap\n");
        return -1;
    }
    check_log();
    ret = check_pcap() ? 1 : 0;
    PRINT_WARN("For this test, log is only a reference. \
Your implementation is OK if your pcap file is the same to the demo pcap file.\n");
    fclose(demo_log);
    fclose(out_log);
    return ret ? -1 : 0;
}