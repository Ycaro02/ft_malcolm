#include "../libft/libft.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/socket.h>

#define BUF_SIZE 1024

void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

char *get_mac_addr(unsigned char *mac) {
    char *res = ft_calloc(13, sizeof(char));

    if (!res)
        return NULL;
    sprintf((char *)res, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
    return (res);
}

void dbg_display_arp_packet(const unsigned char *buffer, ssize_t len) {

        DBG("Packet received, length: %zd bytes\n\n", len);


        struct ethhdr *eth = (struct ethhdr *) buffer;

        // Dump entête Ethernet
        INFO("=== Ethernet Header ===\n");

        char *dest_mac = get_mac_addr(eth->h_dest);
        char *src_mac = get_mac_addr(eth->h_source);

        printf("\n\tDestination MAC : %s\n", dest_mac);
        printf("\n\tSource MAC      : %s\n", src_mac);

        free(dest_mac);
        free(src_mac);


        printf("\n\tProtocol (hex)  : 0x%04x\n\n", ntohs(eth->h_proto));

        // Vérifie que c’est bien une trame ARP
        if (ntohs(eth->h_proto) == ETH_P_ARP) {

            DBG("Received ARP packet, protocol: 0x%04x\n", ntohs(eth->h_proto));

            struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ethhdr));

            INFO("=== ARP Header ===\n");
            printf("\n\tHardware type   : %u\n", ntohs(arp->ea_hdr.ar_hrd));
            printf("\tProtocol type   : 0x%04x\n", ntohs(arp->ea_hdr.ar_pro));
            printf("\tHW size         : %u\n", arp->ea_hdr.ar_hln);
            printf("\tProtocol size   : %u\n", arp->ea_hdr.ar_pln);
            printf("\tOpcode          : %u (%s)\n",
                   ntohs(arp->ea_hdr.ar_op),
                   (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) ? "request" :
                   (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY)   ? "reply"   : "other");

            char sender_ip[INET_ADDRSTRLEN];
            char target_ip[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, arp->arp_spa, sender_ip, sizeof(sender_ip));
            inet_ntop(AF_INET, arp->arp_tpa, target_ip, sizeof(target_ip));

            char *s_mac = get_mac_addr(arp->arp_sha);
            char *t_mac = get_mac_addr(arp->arp_tha);

            printf("\n\tSender MAC      : %s\n", s_mac);
            printf("\tSender IP       : %s\n", sender_ip);

            printf("\n\tTarget MAC      : %s\n", t_mac);
            printf("\tTarget IP       : %s\n", target_ip);

            free(s_mac);
            free(t_mac);

            if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) {
                DBG(">>> ARP Request: Who has %s? Tell %s\n", target_ip, sender_ip);
            }
        } else {
            WARN("Received non-ARP packet, protocol: 0x%04x\n", ntohs(eth->h_proto));
        }
}


void display_arp_packet(const unsigned char *buffer, ssize_t len) {

    (void)len;

    struct ethhdr *eth = (struct ethhdr *) buffer;

    int is_arp = (ntohs(eth->h_proto) == ETH_P_ARP);

    if (!is_arp) {
        ERR("Not an ARP packet, protocol: 0x%04x\n", ntohs(eth->h_proto));
        return;
    }

    struct ether_arp arp_hdr = *(struct ether_arp *)(buffer + sizeof(struct ethhdr));
    int packet_type = ntohs(arp_hdr.ea_hdr.ar_op) == ARPOP_REQUEST ? ARPOP_REQUEST : ntohs(arp_hdr.ea_hdr.ar_op) == ARPOP_REPLY ? ARPOP_REPLY : -1;

    char *packet_type_str = (packet_type == ARPOP_REQUEST) ? YELLOW"REQUEST"RESET : (packet_type == ARPOP_REPLY) ? GREEN"REPLY"RESET : RED"UNKNOWN"RESET;

    INFO("Received ARP [%s] packet\n", packet_type_str);

    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, arp_hdr.arp_spa, sender_ip, sizeof(sender_ip));
    inet_ntop(AF_INET, arp_hdr.arp_tpa, target_ip, sizeof(target_ip));

    char *s_mac = get_mac_addr(arp_hdr.arp_sha);
    char *t_mac = get_mac_addr(arp_hdr.arp_tha);

    INFO("  Sender MAC : %s\n", s_mac);
    INFO("  Sender IP  : %s\n", sender_ip);
    INFO("  Target MAC : %s\n", t_mac);
    INFO("  Target IP  : %s\n\n", target_ip);

}



void listen_arp(char *device_name) {
    char buffer[BUF_SIZE] = {}; /*Buffer for Ethernet Frame*/

    struct ifreq ifr;
    struct sockaddr_ll socket_address;
    unsigned int ifindex = 0;     /*Ethernet Interface index*/

    DBG("Server started, entering initialiation phase...\n");

    /*open socket*/
    errno = 0;
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s == -1) {
        perror("socket:");
        exit(1);
    }
    DBG("Successfully opened socket: %i\n", s);

    /*retrieve ethernet interface index*/
    ft_strlcpy(ifr.ifr_name, device_name, IFNAMSIZ);

    errno = 0;
    ifindex = if_nametoindex(device_name);
    if (ifindex == 0) {
        perror("if_nametoindex:");
        exit(1);
    }
    DBG("Successfully got interface index: %i\n", ifindex);

    /*prepare sockaddr_ll*/
    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = ARPHRD_ETHER;
    socket_address.sll_pkttype = PACKET_OTHERHOST;
    socket_address.sll_halen = 0;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    while (1) {
        errno = 0;
        ssize_t length = recvfrom(s, buffer, BUF_SIZE, 0, NULL, NULL);
        if (length == -1) {
            perror("recvfrom:");
            exit(1);
        }
        INFO("Received packet of length: %ld\n", length);
        // dbg_display_arp_packet((unsigned char *)buffer, length);
        display_arp_packet((unsigned char *)buffer, length);
        ft_bzero(buffer, BUF_SIZE);
    }
}


typedef struct StatusIff {
    unsigned int flag;
    char *name;
} StatusIff;

#define IFF_FLAGS_ARR (StatusIff[]) {\
    { IFF_UP, "IFF_UP" },\
    { IFF_BROADCAST, "IFF_BROADCAST" },\
    { IFF_DEBUG, "IFF_DEBUG" },\
    { IFF_LOOPBACK, "IFF_LOOPBACK" },\
    { IFF_POINTOPOINT, "IFF_POINTOPOINT" },\
    { IFF_NOTRAILERS, "IFF_NOTRAILERS" },\
    { IFF_RUNNING, "IFF_RUNNING" },\
    { IFF_NOARP, "IFF_NOARP" },\
    { IFF_PROMISC, "IFF_PROMISC" },\
    { IFF_ALLMULTI, "IFF_ALLMULTI" },\
    { IFF_MASTER, "IFF_MASTER" },\
    { IFF_SLAVE, "IFF_SLAVE" },\
    { IFF_MULTICAST, "IFF_MULTICAST" },\
    { IFF_PORTSEL, "IFF_PORTSEL" },\
    { IFF_AUTOMEDIA, "IFF_AUTOMEDIA" },\
    { IFF_DYNAMIC, "IFF_DYNAMIC" },\
    { 0, NULL }\
};

#define MAX_FLAGS 16

void display_iff_flag(u32flag) {
    char buffer[1024] = {};
    int idx = 0;

    StatusIff iff_flag_array[] = IFF_FLAGS_ARR;

    for (int i = 0; iff_flag_array[i].flag != 0; i++) {
        if (flag & iff_flag_array[i].flag) {
            idx += sprintf(buffer + idx, " %s", iff_flag_array[i].name);
        }
    }
    INFO("FLAG: %s\n", buffer);
}

s8 is_broadcast_if(u32 flag) {
    return (flag & IFF_BROADCAST);
}

s8 is_loopback_if(u32 flag) {
    return (flag & IFF_LOOPBACK);
}

s8 is_up_if(u32 flag) {
    return (flag & IFF_UP);
}

#include <ifaddrs.h>

void display_ifaddrs(struct ifaddrs *ifa) {
    
    INFO("--------------------------------------------------------------------------------------\n");
    

    if (ifa->ifa_addr->sa_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        INFO("Interface: %s, Address: %s\n", ifa->ifa_name, ip);
        INFO("Flags: 0x%x\n", ifa->ifa_flags);
        display_iff_flag(ifa->ifa_flags);
        if (ifa->ifa_netmask) {
            struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;
            char nm[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &netmask->sin_addr, nm, sizeof(nm));
            INFO("Netmask: %s\n", nm);
        }
        if (ifa->ifa_broadaddr) {
            struct sockaddr_in *broadaddr = (struct sockaddr_in *)ifa->ifa_broadaddr;
            char ba[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &broadaddr->sin_addr, ba, sizeof(ba));
            INFO("Broadcast Address: %s\n", ba); 
        }
    }
}

/**
 *	@brief Get process ipv4 address
 *	@return in_addr_t ipv4 address of the process
*/
s8 iter_ifaddr_lst()
{
    struct ifaddrs *ifa_head, *current;

    errno = 0;
    if (getifaddrs(&ifa_head) == -1) {
        perror("getifaddrs");
        return (0);
    }

    for (current = ifa_head; current != NULL; current = current->ifa_next) {
        if (current->ifa_addr && current->ifa_addr->sa_family == AF_INET) {
            display_ifaddrs(current);
        }
    }
    INFO("--------------------------------------------------------------------------------------\n");
    freeifaddrs(ifa_head);
    return (1);
}


int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    set_log_level(L_DEBUG);
    
    if (argc != 2) {
        ERR("Usage: %s <network interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    iter_ifaddr_lst();
    listen_arp(argv[1]);
}
