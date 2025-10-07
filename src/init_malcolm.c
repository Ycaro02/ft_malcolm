
#include "../include/ft_malcolm.h"

#ifdef MALCOLM_BONUS

    /**
     * @brief Initialize flag options for bonus features
     * @param argc Argument count from command line
     * @param argv Argument vector from command line
     * @param error_flag Pointer to an s8 variable to indicate errors
     * @return u32 Bitmask of parsed flags
     */
    static u32 init_flag_options(int argc, char **argv, s8 *error_flag) {
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

#endif

/**
 * @brief Signal handler for SIGINT
 * @param sig Signal number
 * @note This function sets a global flag to indicate that a signal was received
 */
static void handle_sigint(int sig) {
    (void)sig;
    INFO("Caught SIGINT, exiting...\n");
    g_signal_received = 1;
}

/**
 * @brief Initialize signal handling for SIGINT
 */
static void init_signal_handling(void) {
    struct sigaction sa = {};
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
}

/**
 * @brief Display usage information and exit
 */
static void usage() {
    printf("%s", MALCOLM_USAGE_STR);
    exit(EXIT_SUCCESS);
}

/**
 * @brief Parse command-line input arguments and populate the MalcolmCtx structure
 * @param c Pointer to the MalcolmCtx structure to populate
 * @param cli_args Linked list of command-line arguments
 * @return s8 TRUE on success, FALSE on failure
 */
static s8 parse_input(MalcolmCtx *c, List *cli_args) {
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
static void display_ctx(MalcolmCtx *c) {
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


/**
 * @brief Initialize the Malcolm context and parse command-line arguments
 * @param c Pointer to the MalcolmCtx structure to initialize
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 */
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
