#include "../include/ft_malcolm.h"

/* Ip address string format to bin format */
static Addr ipv4_str_toaddr(char *str) {
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
#ifdef MALCOLM_BONUS

    static Addr hostname_to_ipv4_addr(char *hostname) {
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

#endif

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
