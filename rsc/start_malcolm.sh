#!/bin/bash

LOCAL_IP=$(ip a | grep eth0 | grep inet | awk '{print $2}' | cut -d '/' -f1)

LOCAL_MAC=$(ip a | grep eth0 -C1 | grep 'link/ether' | awk '{print $2}')


echo "Starting Malcolm with IP: ${LOCAL_IP} and MAC: ${LOCAL_MAC}"

TARGET_IP=${1}
TARGET_MAC=${2}

if [ -z "${TARGET_IP}" ] || [ -z "${TARGET_MAC}" ]; then
    echo "Usage: $0 <TARGET_IP> <TARGET_MAC>"
    exit 1
fi

echo "Command: ./ft_malcolm ${TARGET_IP} ${TARGET_MAC} ${LOCAL_IP} ${LOCAL_MAC}"

./ft_malcolm ${TARGET_IP} ${TARGET_MAC} ${LOCAL_IP} ${LOCAL_MAC}