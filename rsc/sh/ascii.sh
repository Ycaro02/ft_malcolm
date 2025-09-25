#!/bin/bash

source ./rsc/sh/color.sh

function print_color_line {
    local color=${1}
    local line="${2}"

    echo -e ${color}"${line}" "${RESET}"

}

function malcolm_ascii {

    local color=${1}
    print_color_line ${color} "MALCOLM"

}

ASCII_NAME=${1}

malcolm_ascii ${GREEN}
