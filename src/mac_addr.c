#include "../include/ft_malcolm.h"

/**
 * @brief Convert a single hexadecimal character to its binary value
 * @param c Hexadecimal character (0-9, a-f, A-F)
 * @return Binary value of the hexadecimal character (0-15), or 0 for invalid
 */
static u8 hex_byte_to_bin(char c) {

    c = ft_tolower(c);

    if (c >= '0' && c <= '9') {
        return (c - '0');
    } else if (c >= 'a' && c <= 'f') {
        return (c - 'a' + 10);
   }
   return 0;
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
 * @brief Check if a character is a valid hexadecimal character
 * @param c Character to check
 * @return s8 TRUE if the character is hexadecimal, FALSE otherwise
 */
static s8 is_hexa_char(char c) {
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
// void test_mac_addr_func() {

//     char *valid_mac = "01:23:45:67:89:ab";
//     char *invalid_mac1 = "01:23:45:67:89";        // Too few octets
//     char *invalid_mac2 = "01:23:45:67:89:gh";     // Invalid hex character
//     char *invalid_mac3 = "01:23:45:67:89:ab:cd";  // Too many octets
//     char *invalid_mac4 = "01-23-45-67-89-ab";     // Wrong delimiter
//     char *invalid_mac5 = "0123:45:67:89:ab";    // Octet too long
//     char *invalid_mac6 = "01:2:45:67:89:ab";     // Octet too short

//     INFO("Testing valid MAC address '%s': %s\n", valid_mac, is_mac_addr(valid_mac) ? GREEN"Valid"RESET : RED"Invalid"RESET);
//     INFO("Testing invalid MAC address '%s': %s\n", invalid_mac1, is_mac_addr(invalid_mac1) ? GREEN"Valid"RESET : RED"Invalid"RESET);
//     INFO("Testing invalid MAC address '%s': %s\n", invalid_mac2, is_mac_addr(invalid_mac2) ? GREEN"Valid"RESET : RED"Invalid"RESET);
//     INFO("Testing invalid MAC address '%s': %s\n", invalid_mac3, is_mac_addr(invalid_mac3) ? GREEN"Valid"RESET : RED"Invalid"RESET);
//     INFO("Testing invalid MAC address '%s': %s\n", invalid_mac4, is_mac_addr(invalid_mac4) ? GREEN"Valid"RESET : RED"Invalid"RESET);
//     INFO("Testing invalid MAC address '%s': %s\n", invalid_mac5, is_mac_addr(invalid_mac5) ? GREEN"Valid"RESET : RED"Invalid"RESET);
//     INFO("Testing invalid MAC address '%s': %s\n", invalid_mac6, is_mac_addr(invalid_mac6) ? GREEN"Valid"RESET : RED"Invalid"RESET);

// }


