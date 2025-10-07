#!/bin/bash

source $(pwd)/rsc/sh/bash_log.sh

ROOT_DIR=$(pwd)

source ${ROOT_DIR}/rsc/sh/bash_log.sh

DC_CMD="docker compose -f rsc/tester/docker-compose.yml"
DC_EXEC="${DC_CMD} exec"

# MAKEFILE_RULE="sleep"
MAKEFILE_RULE="bonus_mitm"

log I "Preparing .env file for tester stack ROOT_DIR=${ROOT_DIR}\n"
echo "ROOT_DIR=${ROOT_DIR}" > ./rsc/tester/.env
echo "MAKEFILE_RULE=${MAKEFILE_RULE}" >> ./rsc/tester/.env

${DC_CMD} up -d --build

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function get_container_ip() {
    # Return the IPv4 address of eth0 for a container (no TTY)
    ${DC_EXEC} "$1" ip addr show eth0 | grep inet | awk '{print $2}' | cut -d '/' -f1 | tr -d '\n'
}

function get_container_mac() {
    # Return the MAC address of eth0 for a container (no TTY)
    ${DC_EXEC} "$1" ip link show eth0 | grep link | awk '{print $2}'
}

# Configuration
INTERFACE="eth0"

TARGET_ONE="target"
TRIGGERS_ONE="trigger"

MITM_MACHINE="ft_malcolm"

MITM_IP=$(get_container_ip "${MITM_MACHINE}")
MITM_MAC=$(get_container_mac "${MITM_MACHINE}")

TARGET_IP=$(get_container_ip "${TARGET_ONE}")
TARGET_MAC=$(get_container_mac "${TARGET_ONE}")

TRIGGERS_IP=$(get_container_ip "${TRIGGERS_ONE}")
TRIGGERS_MAC=$(get_container_mac "${TRIGGERS_ONE}")

TEST_PORT="4242"
SECRET_MESSAGE="Koala Secret Message"

# TCPDUMP_TIMEOUT=10
log I "${BLUE}======================================${RESET}\n"
log I "${BLUE}   MITM Attack Automated Test${RESET}\n"
log I "${BLUE}======================================${RESET}\n\n"

# Step 1: Check initial ARP tables
log I "${BLUE}[1/5]${RESET} Checking initial ARP tables...\n"
log I "Target ARP table:\n"
${DC_EXEC} "${TARGET_ONE}" ip neigh | grep "${TRIGGERS_IP}" || log I "No entry for ${TRIGGERS_IP}\n"
log I "Triggers ARP table:\n"
${DC_EXEC} "${TRIGGERS_ONE}" ip neigh | grep "${TARGET_IP}" || log I "No entry for ${TARGET_IP}\n"

# Step 2: Start tcpdump in background
log I "${BLUE}[2/5]${RESET} Starting tcpdump to capture traffic...\n"
${DC_EXEC} ft_malcolm tcpdump -i "${INTERFACE}" -n -l -A "tcp port ${TEST_PORT}" > /tmp/tcpdump_capture.txt 2>&1 &
sleep 2

# Wait for ARP poisoning to take effect
log I "${YELLOW}Waiting for ARP poisoning to take effect (5 seconds)...${RESET}\n"
sleep 5

# Step 3: Verify ARP poisoning
log I "${BLUE}[3/5]${RESET} Verifying ARP poisoning...\n"

log I "Target ARP table:\n"
log I "$(${DC_EXEC} "${TARGET_ONE}" ip neigh | grep "${TRIGGERS_IP}")"
echo ""

log I "Triggers ARP table:\n"
log I "$(${DC_EXEC} "${TRIGGERS_ONE}" ip neigh | grep "${TARGET_IP}")"
echo ""

log I "Our MAC: ${YELLOW}${MITM_MAC}${RESET}\n"

TARGET_ARP=$(${DC_EXEC} "${TARGET_ONE}" ip neigh | grep "${TRIGGERS_IP}")
TRIGGERS_ARP=$(${DC_EXEC} "${TRIGGERS_ONE}" ip neigh | grep "${TARGET_IP}")

if echo "${TARGET_ARP}" | grep -qi "${MITM_MAC}"; then
    log I "${GREEN}[OK]${RESET} Target successfully poisoned!\n"
else
    log W "Target might not be fully poisoned yet...\n"
fi

if echo "${TRIGGERS_ARP}" | grep -qi "${MITM_MAC}"; then
    log I "${GREEN}[OK]${RESET} Triggers successfully poisoned!\n"
else
    log W "Triggers might not be fully poisoned yet...\n"
fi
echo ""

# Step 4: Start nc listener
log I "${BLUE}[4/5]${RESET} Starting netcat listener on target...\n"
${DC_EXEC} -d "${TARGET_ONE}" sh -c "nc -lvp ${TEST_PORT} -q 0 > /tmp/nc_out.log 2>&1"
sleep 1
log I "${GREEN}[OK]${RESET} Listener started on ${TARGET_IP}:${TEST_PORT}\n"
echo ""

# Step 5: Send the test message
log I "${BLUE}[5/5]${RESET} Sending test message...\n"
log I "Message: ${YELLOW}${SECRET_MESSAGE}${RESET}\n"

${DC_EXEC} -i "${TRIGGERS_ONE}" bash -c "echo \"${SECRET_MESSAGE}\" | nc ${TARGET_ONE} ${TEST_PORT} -q 0"

log I "${GREEN}[OK]${RESET} Message sent from triggers to target\n"
echo ""

log I "${YELLOW}Waiting for traffic to be captured (10 seconds)...${RESET}\n\n"

# Wait a bit to capture the traffic
sleep 10

# Analyze the tcpdump capture
log I "${BLUE}======================================${RESET}\n"
log I "${BLUE}   Results${RESET}\n"
log I "${BLUE}======================================${RESET}\n\n"

if grep -qi "$SECRET_MESSAGE" /tmp/tcpdump_capture.txt; then
    log I "${GREEN}[SUCCESS]${RESET} Message intercepted by MITM!\n"
    log I "${GREEN}The message was captured in tcpdump:${RESET}\n"
else
    log E "${RED}[FAIL]${RESET} Message NOT intercepted\n"
    log E "${YELLOW}Last 20 lines of tcpdump output:${RESET}\n"
    tail -20 /tmp/tcpdump_capture.txt
fi

log I "${BLUE}Full capture saved to: /tmp/tcpdump_capture.txt${RESET}\n"
