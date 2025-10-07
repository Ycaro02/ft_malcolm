#include "../include/ft_malcolm.h"

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
    
    char source_ip_str[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &c->src_ip, source_ip_str, sizeof(source_ip_str));

    char source_mac_str[18] = {};

    EtherArp *arp = (EtherArp *)(c->arp_reply_packet + sizeof(EthHdr));

    inet_ntop(AF_INET, arp->arp_spa, source_ip_str, sizeof(source_ip_str));

    // mac_addr_byte_to_str(c->src_mac, source_mac_str);
    mac_addr_byte_to_str(arp->arp_sha, source_mac_str);

    INFO("Packet sent successfully:\n");
    INFO("%s is at %s\n", source_ip_str, source_mac_str);

    return (TRUE);
}

/**
 * @brief Build an ARP reply packet based on the provided context
 * @param c Pointer to the MalcolmCtx structure containing context information
 * @param buff Pointer to the buffer where the ARP reply packet will be constructed
 */
void build_packet(u8 *buff, Addr src_ip, u8 *src_mac, Addr target_ip, u8 *target_mac) {
    EthHdr eth_resp;

    ft_memcpy(eth_resp.h_dest, target_mac, ETH_ALEN);
    ft_memcpy(eth_resp.h_source, src_mac, ETH_ALEN);
    eth_resp.h_proto = htons(ETH_P_ARP);

    EtherArp arp_hdr_resp;
    arp_hdr_resp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr_resp.ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_hdr_resp.ea_hdr.ar_hln = ETH_ALEN;
    arp_hdr_resp.ea_hdr.ar_pln = 4;
    arp_hdr_resp.ea_hdr.ar_op = htons(ARPOP_REPLY);
   
    ft_memcpy(arp_hdr_resp.arp_spa, &src_ip, 4);
    ft_memcpy(arp_hdr_resp.arp_tpa, &target_ip, 4);
    ft_memcpy(arp_hdr_resp.arp_tha, target_mac, ETH_ALEN);
    ft_memcpy(arp_hdr_resp.arp_sha, src_mac, ETH_ALEN);


    DBG(YELLOW"=== ARP Reply Packet BUILD ===\n"RESET);
    // unsigned char buff[BUFF_SIZE] = {};
    ft_memcpy(buff, &eth_resp, sizeof(EthHdr));
    ft_memcpy(buff + sizeof(EthHdr), &arp_hdr_resp, sizeof(EtherArp));
    DBG("-----------------------------------------------------------------------------------------------\n");
    dbg_display_arp_packet(buff, sizeof(EthHdr) + sizeof(EtherArp));
    DBG("-----------------------------------------------------------------------------------------------\n");

}
