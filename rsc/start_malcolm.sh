#!/bin/bash


# LOCAL_IP=$(ip a | grep eth0 | grep inet | awk '{print $2}' | cut -d '/' -f1)
# LOCAL_MAC=$(ip a | grep eth0 -C1 | grep 'link/ether' | awk '{print $2}')
# ./ft_malcolm 172.18.0.4 aa:aa:aa:aa:aa:aa 172.18.0.3 02:42:ac:12:00:03


SOURCE_IP=${1}
SOURCE_MAC=${2}
TARGET_IP=${3}
TARGET_MAC=${4}

echo "Starting Malcolm: ./ft_malcolm ${SOURCE_IP} ${SOURCE_MAC} ${TARGET_IP} ${TARGET_MAC}"

./ft_malcolm ${SOURCE_IP} ${SOURCE_MAC} ${TARGET_IP} ${TARGET_MAC}