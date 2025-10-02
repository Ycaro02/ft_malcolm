#include "../include/ft_malcolm.h"

/* Global variable to handle signal interruptions */
int  g_signal_received = 0;

/* Main function to run the Malcolm ARP spoofer */
void ft_malcolm(MalcolmCtx *c) {
    char interface_name[BUFF_SIZE] = {};
    s8 ret = get_interface_name(interface_name);
    if (!ret) {
        ERR("Failed to get network interface\n");
        exit(EXIT_FAILURE);
    }

    INFO("Using interface: %s\n", interface_name);
    init_malcolm_sender(&c->sender, interface_name);

    if (has_flag(c->flags, FLAG_MITM)) {
        INFO("Starting MITM attack...\n");
        mitm_attack(c);
        return;
    }
    listen_arp_request(c);
}

int main(int argc, char **argv) {
    
    MalcolmCtx ctx = {0};
    
    set_log_level(L_INFO);


    init_malcolm(&ctx, argc, argv);
    ft_malcolm(&ctx);

    return (0);
}
