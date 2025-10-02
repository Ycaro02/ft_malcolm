#include  "../include/ft_malcolm.h"

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
static s8 is_match_request(MalcolmCtx *c, unsigned char *arp_spa, unsigned char *arp_tpa) {
    char tpa[BUFF_SIZE] = {};
    char *tmp = inet_ntoa(*(InAddr *)arp_tpa);

    ft_strlcpy(tpa, tmp, ft_strlen(tmp));

    INFO("Received ARP Request: Who has %s? Tell %s\n", tpa, inet_ntoa(*(InAddr *)arp_spa));

    if (*(Addr *)arp_tpa == c->src_ip && *(Addr *)arp_spa != c->src_ip) {
        return (TRUE);
    }
    return (FALSE);
}


/**
 * @brief Process incoming ARP requests and send replies if they match the context
 * @param c Pointer to the MalcolmCtx structure containing context information
 * @param buffer Pointer to the received packet buffer
 * @param len Length of the received packet
 */
static void process_arp_request(MalcolmCtx *c, const unsigned char *buffer, ssize_t len) {

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
void listen_arp_request(MalcolmCtx *c) {
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

