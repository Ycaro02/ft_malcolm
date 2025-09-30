#include "../include/ft_malcolm.h"

/**
 * @brief Display interface flags in a human-readable format
 * @param flag Interface flags
 */
static void display_iff_flag(u32 flag) {
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
 * @brief Debug function to display interface information
 * @param ifa Pointer to the IfAddrs structure containing interface information
 */
static void display_ifaddrs(IfAddrs *ifa) {
    
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
 * @brief Check if the interface is a broadcast interface
 * @param flag Interface flags
 * @return s8 TRUE if the interface is a broadcast, FALSE otherwise
 */
static s8 is_broadcast_if(u32 flag) {
    return (flag & IFF_BROADCAST);
}

/**
 * @brief Check if the interface is a loopback interface
 * @param flag Interface flags
 * @return s8 TRUE if the interface is a loopback, FALSE otherwise
 */
static s8 is_loopback_if(u32 flag) {
    return (flag & IFF_LOOPBACK);
}

/**
 * @brief Check if the interface is up
 * @param flag Interface flags
 * @return s8 TRUE if the interface is up, FALSE otherwise
 */
static s8 is_up_if(u32 flag) {
    return (flag & IFF_UP);
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
