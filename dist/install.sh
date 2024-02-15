#! /bin/bash
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