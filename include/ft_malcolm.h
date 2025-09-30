#ifndef FT_MALCOLM_H
#define FT_MALCOLM_H

#include "../libft/libft.h"
#include "../libft/parse_flag/parse_flag.h"

#include <sys/socket.h>         /* socket */
#include <arpa/inet.h>          /* inet_ntoa ... */
#include <net/if.h>             /* if_nametoindex ... */
#include <netinet/if_ether.h>   /* struct ethhdr, ether_arp ... */
#include <netpacket/packet.h>   /* struct sockaddr_ll ... */
#include <netdb.h>              /* struct addrinfo ... */
#include <ifaddrs.h>            /* getifaddrs ... */
#include <signal.h>             /* signal handling ... */

/* Global variable to handle signal interruptions */
extern int  g_signal_received;

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

/* Flag options */
typedef enum FlagOptionVal {
    FLAG_HELP = 1U,
    FLAG_LOG_VERBOSITY = 2U,
} FlagOptionVal;

/* Flag option strings and characters */
#define FLAG_HELP_CHAR 'h'
#define FLAG_HELP_STR "help"

#define FLAG_LOG_VERBOSITY_CHAR 'v'
#define FLAG_LOG_VERBOSITY_STR "verbosity"

#define MALCOLM_BONUS_USAGE \
"Usage: ./ft_malcolm [options] <src_ip> <src_mac> <target_ip> <target_mac>\n"\
"Options:\n"\
"  -h, --help               Show this help message and exit\n"\
"  -v, --verbosity <level>  Set log verbosity level (1-4 or none, error, warn, info, debug)\n"

#define MALCOLM_STANDARD_USAGE \
"Usage: ./ft_malcolm <src_ip> <src_mac> <target_ip> <target_mac>\n"


#ifdef MALCOLM_BONUS
    #define MALCOLM_USAGE_STR MALCOLM_BONUS_USAGE
#else
    #define MALCOLM_USAGE_STR MALCOLM_STANDARD_USAGE
#endif



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


/* Function prototypes */

/* mac_addr.c */
void    mac_addr_str_to_bytes(const char *mac_str, unsigned char *mac_bytes);
void    mac_addr_byte_to_str(unsigned char *mac, char *buf);
s8      is_mac_addr(char *mac);

/* ipv4_addr.c */
s8      is_ipv4_addr(char *dest_str, Addr *dest_addr);

/* network_interface.c */
s8      get_interface_name(char *interface_name);

#endif /* FT_MALCOLM_H */