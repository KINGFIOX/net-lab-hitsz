#include "arp.h"
#include "buf.h"
#include "driver.h"
#include "ethernet.h"
#include "ip.h"
#include "testing/log.h"
#include "udp.h"

#include <stdio.h>
#include <string.h>

extern FILE *pcap_out;
extern FILE *pcap_in;
extern FILE *control_flow;
extern FILE *icmp_fout;
extern FILE *udp_fout;
extern FILE *out_log;
extern FILE *arp_log_f;

char *print_ip(uint8_t *ip);
char *print_mac(uint8_t *mac);

uint8_t my_mac[] = NET_IF_MAC;
uint8_t boardcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char *state[16];

uint8_t dst_mac[] = {0xbe, 0x67, 0x30, 0x9c, 0xb6, 0x46};

int check_log();
int check_pcap();
void log_tab_buf();
FILE *open_file(char *path, char *name, char *mode);

buf_t buf;
int main(int argc, char *argv[]) {
    PRINT_INFO("Test begin.\n");
    int ret;
    pcap_in = open_file(argv[1], "in.pcap", "r"); // dummy
    pcap_out = open_file(argv[1], "out.pcap", "w");
    control_flow = open_file(argv[1], "log", "w");
    FILE *fp_text = open_file(argv[1], "in.txt", "r");
    if (pcap_out == 0 || control_flow == 0 || fp_text == 0) {
        if (pcap_out)
            fclose(pcap_out);
        else
            PRINT_ERROR("Failed to open out.pcap\n");
        if (control_flow)
            fclose(control_flow);
        else
            PRINT_ERROR("Failed to open log\n");
        if (fp_text)
            fclose(fp_text);
        else
            PRINT_ERROR("Failed to open input text\n");
        return -1;
    }
    icmp_fout = control_flow;
    udp_fout = control_flow;
    arp_log_f = control_flow;

    ret = net_init();
    if (ret == -1) {
        return -1;
    }
    log_tab_buf();

    // count file size
    fseek(fp_text, 0, SEEK_END);
    size_t content_length = ftell(fp_text);
    fseek(fp_text, 0, SEEK_SET);
    ret = buf_init(&buf, content_length);
    if (ret != 0) {
        return -1;
    }
    fread(buf.data, content_length, 1, fp_text);
    udp_out(&buf, 8080, dst_mac, 8080);

    driver_close();
    PRINT_INFO("\nSample input all processed, checking output\n");

    // fclose(control_flow);
    // fclose(out_log);
    // fclose(fp_text);
    // fclose(pcap_out);
    return 0;
}