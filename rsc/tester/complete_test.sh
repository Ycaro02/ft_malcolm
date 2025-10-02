#!/bin/bash

ROOT_DIR=$(pwd)

source ${ROOT_DIR}/rsc/sh/bash_log.sh

DC_CMD="docker compose -f rsc/tester/docker-compose.yml"

MAKEFILE_RULE="${1:-test}"

if [ "${MAKEFILE_RULE}" != "test" ] && [ "${MAKEFILE_RULE}" != "btest" ]; then
    log E "Invalid Makefile rule specified. Use 'test' or 'btest'.\n"
    exit 1
fi

log I "Preparing .env file for tester stack ROOT_DIR=${ROOT_DIR}\n"
echo "ROOT_DIR=${ROOT_DIR}" > ./rsc/tester/.env
echo "MAKEFILE_RULE=${MAKEFILE_RULE}" >> ./rsc/tester/.env

MALCOLM_ARGS=$(grep -w "${MAKEFILE_RULE}:" Makefile -C1 | grep ./ft_malcolm)

log I "Starting test up the stack...\n"
log I "Running malcolm with args: ${MALCOLM_ARGS}\n"
${DC_CMD} up -d > /dev/null 2>&1

sleep 2

log I "Sending ARP request from trigger container...\n"
${DC_CMD} exec -it trigger arping -c 1 10.12.255.255 > /dev/null 2>&1

sleep 5

log I "Checking if target received the ARP request...\n"
RES=$(${DC_CMD} exec -it target cat /proc/net/arp | grep 10.12.255.255 | grep "aa:bb:cc:dd:ee:ff")
if [ -n "$RES" ]; then
    log I ${GREEN}"ARP request received by target.\n"${RESET}
    log D "ARP entry: ${RES}\n"
else
    log E ${RED}"ARP request NOT received by target.\n"${RESET}
fi

${DC_CMD} logs ft_malcolm

log I "Down the test stack...\n"
${DC_CMD} exec -it target make fclean > /dev/null 2>&1
${DC_CMD} down -v