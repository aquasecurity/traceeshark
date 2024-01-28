#!/usr/bin/env python3

import argparse
import os
import select
import signal
import struct
import subprocess as subp
import sys
from threading import Thread


DLT_USER0 = 147
TRACEE_OUTPUT_PIPE = '/tmp/tracee_output.pipe'

container_id = None
running = True


def show_version():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Tracee}")


def show_interfaces():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Tracee}")
    print("interface {value=record}{display=Tracee}")


def show_config():
    args = []

    args.append((0, '--image', 'Docker image', 'Tracee docker image to use', 'string', '{required=true}{default=aquasec/tracee:latest}{group=Container options}'))
    args.append((1, '--name', 'Container name', 'Container name to use', 'string', '{default=tracee}{group=Container options}'))
    args.append((2, '--docker-options', 'Docker options', 'Command line options for docker', 'string', '{default=--pid=host --cgroupns=host --privileged -v /etc/os-release:/etc/os-release-host:ro -v /var/run:/var/run:ro -v /sys/fs/cgroup:/sys/fs/cgroup -v /var/run/docker.sock:/var/run/docker.sock}{group=Container options}'))

    for arg in args:
        print("arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg)


def show_dlts():
    print("dlt {number=%d}{name=USER0}{display=Tracee event}" % DLT_USER0)


def get_fake_pcap_header():
    header = bytearray()
    header += struct.pack('<L', int('a1b2c3d4', 16))
    header += struct.pack('<H', 2)  # Pcap Major Version
    header += struct.pack('<H', 4)  # Pcap Minor Version
    header += struct.pack('<I', 0)  # Timezone
    header += struct.pack('<I', 0)  # Accuracy of timestamps
    header += struct.pack('<L', 0xffffffff)  # Max Length of capture frame
    header += struct.pack('<L', DLT_USER0)  # Ethernet
    return header


def write_event(event, extcap_pipe):
    packet = bytearray()

    caplen = len(event)
    timestamp_secs = 0
    timestamp_nsecs = 0

    packet += struct.pack('<L', timestamp_secs) # timestamp seconds
    packet += struct.pack('<L', timestamp_nsecs)  # timestamp nanoseconds
    packet += struct.pack('<L', caplen)  # length captured
    packet += struct.pack('<L', caplen)  # length in frame

    packet += event

    extcap_pipe.write(packet)


def read_output(logs_pipe, extcap_pipe):
    global running

    # open tracee logs pipe and extcap pipe
    logs_pipe_f = os.open(logs_pipe, os.O_RDONLY, os.O_NONBLOCK)
    extcap_pipe_f = open(extcap_pipe, 'wb')

    # write fake PCAP header
    extcap_pipe_f.write(get_fake_pcap_header())

    # read events until the the capture stops
    while running:
        # check if data is available
        rlist, _, _ = select.select([logs_pipe_f], [], [], 0.1)

        # there is data available to read
        if rlist:
            event = os.read(logs_pipe_f, 65536) # sensible max event size
            write_event(event, extcap_pipe_f)
        else:
            continue
    
    os.close(logs_pipe_f)
    extcap_pipe_f.close()


def stop_capture(signum, frame):
    global running, container_id

    running = False

    if container_id is None:
        sys.exit(0)

    command = f'docker kill {container_id}'

    proc = subp.Popen(['/bin/sh', '-c', command], stdout=subp.PIPE, stderr=subp.PIPE)
    _, err = proc.communicate()
    if proc.returncode != 0:
        sys.stderr.write(f'docker wait returned with error code {proc.returncode}, stderr dump:\n{err}')
        sys.exit(0)


def tracee_capture(args: argparse.Namespace):
    if not args.fifo:
        sys.stderr.write('no output pipe provided')
        sys.exit(1)
    
    if not args.image or not args.docker_options:
        sys.stderr.write('no image or docker options provided')
        sys.exit(1)
    
    # create pipe to get events from tracee
    try:
        os.remove(TRACEE_OUTPUT_PIPE)
    except FileNotFoundError:
        pass
    os.mkfifo(TRACEE_OUTPUT_PIPE)

    reader_th = Thread(target=read_output, args=(TRACEE_OUTPUT_PIPE, args.fifo), daemon=True)
    reader_th.start()

    command = 'docker run -d --rm'

    if len(args.name) >= 1:
        command += f' --name {args.name}'
    
    command += f' {args.docker_options} -v {TRACEE_OUTPUT_PIPE}:/output.pipe:rw {args.image} -o json:/output.pipe'

    signal.signal(signal.SIGINT, stop_capture)
    signal.signal(signal.SIGTERM, stop_capture)
    
    proc = subp.Popen(['/bin/sh', '-c', command], stdout=subp.PIPE, stderr=subp.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        sys.stderr.write(f'docker run returned with error code {proc.returncode}, stderr dump:\n{err}')
        sys.exit(1)
    
    global container_id
    container_id = out.decode()

    command = f'docker wait {container_id}'

    proc = subp.Popen(['/bin/sh', '-c', command], stdout=subp.PIPE, stderr=subp.PIPE)
    _, err = proc.communicate()
    if proc.returncode != 0:
        sys.stderr.write(f'docker wait returned with error code {proc.returncode}, stderr dump:\n{err}')
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(prog=os.path.basename(__file__), description='Record events and packets using Tracee')

    # extcap arguments
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")
    parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--capture", help="Start the capture routine", action="store_true")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")

    # custom arguments
    parser.add_argument('--image', type=str)
    parser.add_argument('--name', type=str)
    parser.add_argument('--docker-options', type=str)

    args = parser.parse_args()

    if args.extcap_version and not args.extcap_interfaces:
        show_version()
        sys.exit(0)

    if args.extcap_interfaces or args.extcap_interface is None:
        show_interfaces()
        sys.exit(0)
    
    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit("An interface must be provided or the selection must be displayed")
    
    if args.extcap_config:
        show_config()
    elif args.extcap_dlts:
        show_dlts()
    elif args.capture:
        tracee_capture(args)
    
    sys.exit(0)


if __name__ == '__main__':
    #sys.stderr.write(f'{sys.argv}\n')
    main()
