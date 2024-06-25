#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
from typing import List, Optional


def get_pcap_files(tracee_pcaps_dir: str) -> List[str]:
    pcaps: List[str] = []
    subdirs = os.listdir(tracee_pcaps_dir)

    # Prefer per-process PCAPs
    if 'processes' in subdirs:
        for container in os.listdir(os.path.join(tracee_pcaps_dir, 'processes')):
            for pcap in os.listdir(os.path.join(tracee_pcaps_dir, 'processes', container)):
                pcaps.append(os.path.join(tracee_pcaps_dir, 'processes', container, pcap))
    
    # Next preference is per-command PCAPs
    elif 'commands' in subdirs:
        for container in os.listdir(os.path.join(tracee_pcaps_dir, 'commands')):
            for pcap in os.listdir(os.path.join(tracee_pcaps_dir, 'commands', container)):
                pcaps.append(os.path.join(tracee_pcaps_dir, 'commands', container, pcap))
    
    # Next preference is per-container PCAPs
    elif 'containers' in subdirs:
        for pcap in os.listdir(os.path.join(tracee_pcaps_dir, 'containers')):
            pcaps.append(os.path.join(tracee_pcaps_dir, 'containers', pcap))
    
    # Finally we resort to single PCAP
    elif 'single.pcap' in subdirs:
        pcaps.append(os.listdir(tracee_pcaps_dir, 'single.pcap'))
    else:
        print(f'ERROR: could not find any PCAPs', file=sys.stderr)
        exit(1)
    
    return pcaps


def run_mergecap(mergecap_args: List[str], mergecap_executable: Optional[str] = None):
    command = [mergecap_executable or 'mergecap']
    command.extend(mergecap_args)
    
    try:
        subprocess.run(command)
    except FileNotFoundError:
        # We are in Windows, try finding mergecap in program files
        if os.name == 'nt' and mergecap_executable is None:
            run_mergecap(mergecap_args, mergecap_executable=os.path.join(os.getenv("ProgramFiles"), "Wireshark", "mergecap.exe"))
            return
        print(f'ERROR: cannot find mergecap. Please make sure it is in your PATH.', file=sys.stderr)
        exit(1)


def main():
    parser = argparse.ArgumentParser(description='Merge Tracee events with PCAPs')

    parser.add_argument('-e', '--events', type=str, metavar='FILE', help='Tracee events JSON output (optional)')
    parser.add_argument('-p', '--pcaps', type=str, default='/tmp/tracee/out/pcap', metavar='DIR', help='Tracee PCAPs output dir')
    parser.add_argument('-o', '--output', type=str, default='merged.pcapng', metavar='FILE', help='Output file (pcapng format)')

    args = parser.parse_args()

    # Get list of pcap files
    pcaps = get_pcap_files(args.pcaps)

    # Construct mergecap command and run it
    mergecap_args = ['-w', args.output]
    if args.events is not None:
        mergecap_args.append(args.events)
    mergecap_args.extend([pcap for pcap in pcaps])

    run_mergecap(mergecap_args)
    

if __name__ == '__main__':
    main()
