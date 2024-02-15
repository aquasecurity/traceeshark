#!/bin/bash

WS_VERSION_WANTED=$(cat ws_version.txt | grep -o -P "\d+\.\d+\.\d+")
if command -v "wireshark" &> /dev/null; then
    WS_VERSION_EXISTS=$(wireshark --version | grep -o -P "Wireshark \d+\.\d+\.\d+" | grep -o -P "\d+\.\d+\.\d+")
    if [ "$WS_VERSION_WANTED" != "$WS_VERSION_EXISTS" ]; then
        read -p "Plugins were compiled for Wireshark $WS_VERSION_WANTED but you have version $WS_VERSION_EXISTS, install plugins anyway? (y/n): " user_input
        if [[ "$user_input" != "y" && "$user_input" != "Y" ]]; then
            exit 1
        fi
    fi
else
    read -p "Wireshark installation not found, install plugins anyway? (y/n): " user_input
    if [[ "$user_input" != "y" && "$user_input" != "Y" ]]; then
        exit 1
    fi
fi

mkdir -p ~/.local/lib/wireshark/plugins/epan
cp tracee-event.so* ~/.local/lib/wireshark/plugins/epan
cp tracee-network-capture.so* ~/.local/lib/wireshark/plugins/epan
mkdir -p ~/.local/lib/wireshark/plugins/wiretap
cp tracee-json.so* ~/.local/lib/wireshark/plugins/wiretap
mkdir -p ~/.config/wireshark/profiles
cp -r profiles/Tracee ~/.config/wireshark/profiles/

os_name=$(uname -s)
if [ "$os_name" == "Linux" ]; then
    mkdir -p ~/.local/lib/wireshark/extcap
    cp extcap/tracee-capture.py ~/.local/lib/wireshark/extcap/
    chmod +x ~/.local/lib/wireshark/extcap/tracee-capture.py
    cp -r extcap/tracee-capture ~/.local/lib/wireshark/extcap/
fi