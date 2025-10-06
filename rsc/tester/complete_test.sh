#!/bin/bash

ROOT_DIR=$(pwd)

source ${ROOT_DIR}/rsc/sh/bash_log.sh

log I "Preparing .env file for tester stack ROOT_DIR=${ROOT_DIR}\n"
echo "ROOT_DIR=${ROOT_DIR}" > ./rsc/tester/.env

log I "Starting test up the stack...\n"
docker compose -f rsc/tester/docker-compose.yml up -d > /dev/null 2>&1

log I "Sending ARP request from trigger container...\n"
docker compose -f rsc/tester/docker-compose.yml exec -it trigger arping -c 1 10.12.255.255 > /dev/null 2>&1

log I "Checking if target received the ARP request...\n"
RES=$(docker compose -f rsc/tester/docker-compose.yml exec -it target cat /proc/net/arp | grep 10.12.255.255 | grep "aa:bb:cc:dd:ee:ff")
if [ -n "$RES" ]; then
    log I ${GREEN}"ARP request received by target.\n"${RESET}
    log D "ARP entry: ${RES}\n"
else
    log E ${RED}"ARP request NOT received by target.\n"${RESET}
fi

log I "Down the test stack...\n"
docker compose -f rsc/tester/docker-compose.yml down -v