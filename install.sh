#! /bin/bash
mkdir -p ~/.config/wireshark/profiles
cp -r profiles/Tracee ~/.config/wireshark/profiles/

os_name=$(uname -s)
if [ "$os_name" == "Linux" ]; then
    mkdir -p ~/.local/lib/wireshark/extcap
    cp extcap/tracee-record.py ~/.local/lib/wireshark/extcap/
    chmod +x ~/.local/lib/wireshark/extcap/tracee-record.py
    cp -r extcap/tracee-record ~/.local/lib/wireshark/extcap/
fi