#!/bin/bash



IP_ADDR=${1}

if [ -z "${IP_ADDR}" ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

ARP_ENTRY=$(ip neigh show | grep ${IP_ADDR} | awk '{print $1" "$2" "$3}')

if [ -z "${ARP_ENTRY}" ]; then
    echo "No ARP entry found for IP address ${IP_ADDR}"
    exit 1
fi

echo "Removing ARP entry: ${ARP_ENTRY}"

ip neigh del ${ARP_ENTRY}

echo "ARP entry for IP address ${IP_ADDR} removed successfully"

ip neigh show