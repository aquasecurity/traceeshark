#!/usr/bin/env python3

import argparse
from ctypes import cdll, byref, create_string_buffer
import fcntl
import os
import select
import signal
import struct
import subprocess as subp
import sys
from threading import Thread


DLT_USER0 = 147
TRACEE_OUTPUT_PIPE = '/tmp/tracee_output.pipe'
TRACEE_OUTPUT_PIPE_CAPACITY = 131072 # enough to hold the largest event encountered so far
READER_COMM = 'tracee-record'
TRACEE_LOGS_PATH = '/tmp/tracee_logs.log'

DEFAULT_TRACEE_IMAGE = 'aquasec/tracee:latest'
DEFAULT_DOCKER_OPTIONS = '--pid=host --cgroupns=host --privileged -v /etc/os-release:/etc/os-release-host:ro -v /var/run:/var/run:ro -v /sys/fs/cgroup:/sys/fs/cgroup -v /var/run/docker.sock:/var/run/docker.sock'
DEFAULT_CONTAINER_NAME = 'tracee'

container_id = None
running = True


def show_version():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Tracee}")


def show_interfaces():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Tracee}")
    print("interface {value=record}{display=Tracee}")


def show_config():
    args = []

    args.append((0, '--image', 'Docker image', 'Tracee docker image to use', 'string', '{required=true}{default=%s}{group=Container options}' % DEFAULT_TRACEE_IMAGE))
    args.append((1, '--name', 'Container name', 'Container name to use', 'string', '{default=%s}{group=Container options}' % DEFAULT_CONTAINER_NAME))
    args.append((2, '--docker-options', 'Docker options', 'Command line options for docker', 'string', '{default=%s}{group=Container options}' % DEFAULT_DOCKER_OPTIONS))
    args.append((4, '--tracee-options', 'Tracee options', 'Command line options for tracee', 'string', '{group=Tracee options}'))

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
    header += struct.pack('<L', DLT_USER0)  # custom Tracee JSON encapsulation
    return header


def parse_ts(event: str) -> int:
    if not event.startswith(b'{"timestamp":'):
        raise ValueError(f'invalid event: {event}')
    
    # skip {"timestamp": in the beginning of the event
    return int(event[13: event.find(b',')])


def write_event(event, extcap_pipe):
    packet = bytearray()

    caplen = len(event)
    ts = parse_ts(event)
    timestamp_secs = int(ts / 1000000000)
    timestamp_usecs = int((ts % 1000000000) / 1000)

    # TODO: temporary workaround for tracee timestamp bug
    if timestamp_secs < 0 or timestamp_secs > 2**32-1:
        timestamp_secs = 0
        timestamp_usecs = 0

    packet += struct.pack('<L', timestamp_secs) # timestamp seconds
    packet += struct.pack('<L', timestamp_usecs)  # timestamp microseconds
    packet += struct.pack('<L', caplen)  # length captured
    packet += struct.pack('<L', caplen)  # length in frame

    packet += event

    extcap_pipe.write(packet)


def set_proc_name(newname: str):
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(newname)+1)
    buff.value = newname.encode()
    libc.prctl(15, byref(buff), 0, 0, 0)


def read_output(logs_pipe, extcap_pipe):
    global running

    # change our process name so we can exclude it (otherwise it may flood capture with pipe read activity)
    # TODO: using a PID is more robust, but currently there is no way to filter by PID in namespace (required when running on WSL)
    set_proc_name(READER_COMM)

    # open tracee logs pipe and extcap pipe
    logs_pipe_f = os.open(logs_pipe, os.O_RDONLY, os.O_NONBLOCK)
    fcntl.fcntl(logs_pipe_f, fcntl.F_SETPIPE_SZ, TRACEE_OUTPUT_PIPE_CAPACITY)
    extcap_pipe_f = open(extcap_pipe, 'wb')

    # write fake PCAP header
    extcap_pipe_f.write(get_fake_pcap_header())

    # read events until the the capture stops
    while running:
        # check if data is available
        rlist, _, _ = select.select([logs_pipe_f], [], [], 0.1)

        # there is data available to read
        if rlist:
            data = os.read(logs_pipe_f, TRACEE_OUTPUT_PIPE_CAPACITY)

            # split read data into individual events (TODO: this method might hurt perf, might want to search for newlines while reading)
            for event in data.split(b'\n'):
                if len(event) > 0:
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
        sys.stderr.write(f'docker kill returned with error code {proc.returncode}, stderr dump:\n{err}')
        sys.exit(1)


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

    command = 'docker run -d'

    if len(args.name) > 0:
        command += f' --name {args.name}'
    
    command += f' {args.docker_options} -v {TRACEE_OUTPUT_PIPE}:/output.pipe:rw -v {TRACEE_LOGS_PATH}:/logs.log:rw {args.image}'

    if args.tracee_options and len(args.tracee_options) > 0:
        command += f' {args.tracee_options}'
    
    command += f" --scope comm!='{READER_COMM}' -o json:/output.pipe --log file:/logs.log"

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
    
    # check tracee logs for errors
    command = f'docker logs {container_id}'

    proc = subp.Popen(['/bin/sh', '-c', command], stdout=subp.PIPE, stderr=subp.PIPE)
    _, logs_err = proc.communicate()
    if proc.returncode != 0:
        sys.stderr.write(f'docker logs returned with error code {proc.returncode}, stderr dump:\n{err}')
        sys.exit(1)
    
    command = f'docker rm {container_id}'

    proc = subp.Popen(['/bin/sh', '-c', command], stdout=subp.PIPE, stderr=subp.PIPE)
    _, err = proc.communicate()
    if proc.returncode != 0:
        sys.stderr.write(f'docker rm returned with error code {proc.returncode}, stderr dump:\n{err}')
        sys.exit(1)
    
    if len(logs_err) > 0:
        sys.stderr.write(f'Tracee exited with error message:\n{logs_err.decode()}')
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
    parser.add_argument('--image', type=str, default=DEFAULT_TRACEE_IMAGE)
    parser.add_argument('--name', type=str, default=DEFAULT_CONTAINER_NAME)
    parser.add_argument('--docker-options', type=str, default=DEFAULT_DOCKER_OPTIONS)
    parser.add_argument('--tracee-options', type=str)

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
