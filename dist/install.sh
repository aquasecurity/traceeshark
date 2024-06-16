#!/bin/bash

WS_VERSION_WANTED=$(cat ws_version.txt | grep -o -E "[0-9]+\.[0-9]+\.[0-9]+")
if command -v "wireshark" &> /dev/null; then
    WS_VERSION_EXISTS=$(wireshark --version | grep -o -E "Wireshark [0-9]+\.[0-9]+\.[0-9]+" | grep -o -E "[0-9]+\.[0-9]+\.[0-9]+")
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

mkdir -p $HOME/.config/wireshark/profiles
cp -r profiles/Tracee $HOME/.config/wireshark/profiles/
echo "[*] Installed profile to $HOME/.config/wireshark/profiles/Tracee"

WS_VERSION_SHORT=$(echo $WS_VERSION_EXISTS | grep -o -E "[0-9]+\.[0-9]+")
if [[ $WS_VERSION_SHORT < "4.3" ]]; then
    OS_NAME=$(uname -s)
    if [ "$OS_NAME" == "Linux" ]; then
        WS_VERSION_DIR=$WS_VERSION_SHORT
    else
        WS_VERSION_DIR=${WS_VERSION_SHORT//./-}
    fi
    PLUGINS_DIR="$HOME/.local/lib/wireshark/plugins/$WS_VERSION_DIR"
else
    PLUGINS_DIR="$HOME/.local/lib/wireshark/plugins"
fi

mkdir -p $PLUGINS_DIR/epan
cp tracee-event.so* $PLUGINS_DIR/epan
cp tracee-network-capture.so* $PLUGINS_DIR/epan
mkdir -p $PLUGINS_DIR/wiretap
cp tracee-json.so* $PLUGINS_DIR/wiretap
echo "[*] Installed plugins to $PLUGINS_DIR"

if [[ $WS_VERSION_SHORT < "4.1" ]]; then
    EXTCAP_DIR="$HOME/.config/wireshark/extcap"
else
    EXTCAP_DIR="$HOME/.local/lib/wireshark/extcap"
fi

mkdir -p $EXTCAP_DIR
cp extcap/tracee-capture.py $EXTCAP_DIR
chmod +x $EXTCAP_DIR/tracee-capture.py
cp -r extcap/tracee-capture $EXTCAP_DIR
chmod +x $EXTCAP_DIR/tracee-capture/new-entrypoint.sh
echo "[*] Installed extcap to $EXTCAP_DIR"