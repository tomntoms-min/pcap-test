#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

// Endianness 정의
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define LIBNET_LIL_ENDIAN 1
#define LIBNET_BIG_ENDIAN 0
#elif __BYTE_ORDER == __BIG_ENDIAN
#define LIBNET_LIL_ENDIAN 0
#define LIBNET_BIG_ENDIAN 1
#else
#error "Unknown byte order"
#endif

// libnet-headers.h에서 제공된 구조체
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN]; /* source ethernet address */
    u_int16_t ether_type;                  /* protocol */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;      /* total length */
    u_int16_t ip_id;       /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;       /* time to live */
    u_int8_t ip_p;         /* protocol */
    u_int16_t ip_sum;      /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;    /* source port */
    u_int16_t th_dport;    /* destination port */
    u_int32_t th_seq;      /* sequence number */
    u_int32_t th_ack;      /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,      /* (unused) */
           th_off:4;       /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,     /* data offset */
           th_x2:4;        /* (unused) */
#endif
    u_int8_t  th_flags;    /* control flags */
    u_int16_t th_win;      /* window */
    u_int16_t th_sum;      /* checksum */
    u_int16_t th_urp;      /* urgent pointer */
};

#define MAX_PAYLOAD_PRINT 20

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d (%s)\n", res, pcap_geterr(pcap));
            break;
        }
        
        // 이더넷 헤더 파싱
        if (header->caplen < sizeof(struct libnet_ethernet_hdr))
            continue;
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        
        // IPv4 패킷인지 확인 (0x0800 = IPv4)
        if (ntohs(eth_hdr->ether_type) != 0x0800)
            continue;
        
        // IP 헤더 파싱
        if (header->caplen < sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr))
            continue;
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        
        // TCP 패킷인지 확인 (6 = TCP)
        if (ip_hdr->ip_p != 6) // IPPROTO_TCP
            continue;
        
        // IP 헤더 길이 계산 (4바이트 단위)
        int ip_header_length = ip_hdr->ip_hl * 4;
        if (ip_header_length < 20) // 최소 IP 헤더 길이는 20바이트
            continue;
        
        // TCP 헤더 파싱
        if (header->caplen < sizeof(struct libnet_ethernet_hdr) + ip_header_length + sizeof(struct libnet_tcp_hdr))
            continue;
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header_length);
        
        // TCP 헤더 길이 계산 (4바이트 단위)
        int tcp_header_length = tcp_hdr->th_off * 4;
        if (tcp_header_length < 20) // 최소 TCP 헤더 길이는 20바이트
            continue;
        
        // 전체 헤더 길이 계산
        int total_headers_length = sizeof(struct libnet_ethernet_hdr) + ip_header_length + tcp_header_length;
        
        // 페이로드 위치 및 길이 계산
        int payload_length = header->caplen - total_headers_length;
        if (payload_length < 0)
            payload_length = 0;
        const u_char* payload = packet + total_headers_length;
        
        // 패킷 정보 출력
        printf("\n=====================================================\n");
        
        // Ethernet Header 정보 출력
        printf("[Ethernet Header]\n");
        printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
               eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
        printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
               eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
        
        // IP Header 정보 출력
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        printf("[IP Header]\n");
        printf("  Src IP: %s\n", src_ip);
        printf("  Dst IP: %s\n", dst_ip);
        
        // TCP Header 정보 출력
        printf("[TCP Header]\n");
        printf("  Src Port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("  Dst Port: %d\n", ntohs(tcp_hdr->th_dport));
        
        // 페이로드(Data) 출력 (최대 20바이트)
        printf("[Payload (Data)]\n");
        if (payload_length > 0) {
            int print_length = (payload_length < MAX_PAYLOAD_PRINT) ? payload_length : MAX_PAYLOAD_PRINT;
            printf("  ");
            for (int i = 0; i < print_length; i++) {
                printf("%02x ", payload[i]);
            }
            printf("\n");
        } else {
            printf("  No payload data\n");
        }
    }
    
    pcap_close(pcap);
    return 0;
}
