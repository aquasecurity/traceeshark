#!/usr/bin/env python3

import os
import subprocess

if os.name == 'nt':
    tshark = r'build\run\RelWithDebInfo\tshark.exe'
else:
    tshark = "wireshark/build/run/tshark"

proc = subprocess.Popen([tshark, "-G", "plugins"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = proc.communicate()
if proc.returncode != 0:
    print(f'tshark exited with return code {proc.returncode}, stderr:')
    print(err.decode())
    exit(1)

out = out.decode()
if 'tracee-event' in out and 'tracee-network-capture' in out and 'tracee-json' in out:
    print('Plugins loaded successfully')
    exit(0)
else:
    print("Plugins not loaded. tshark output:")
    print(out)
    print("Tshark errors:")
    print(err.decode())
    exit(1)
