#!/usr/bin/env python3

from typing import List, Optional

import argparse
from ctypes import cdll, byref, create_string_buffer
import fcntl
import os
import shutil
import signal
import struct
import subprocess as subp
import sys
from threading import Thread


DLT_USER0 = 147
TRACEE_OUTPUT_PIPE = '/tmp/tracee_output.pipe'
TRACEE_OUTPUT_PIPE_CAPACITY = 262144 # enough to hold the largest event encountered so far
F_SETPIPE_SZ = 1031 # python < 3.10 does not have fcntl.F_SETPIPE_SZ
READER_COMM = 'tracee-capture'

GENERAL_GROUP = 'General'
TRACEE_OPTIONS_GROUP = 'Tracee options'
PRESET_GROUP = 'Preset control'

DEFAULT_TRACEE_IMAGE = 'aquasec/tracee:latest'
DEFAULT_DOCKER_OPTIONS = '--pid=host --cgroupns=host --privileged -v /etc/os-release:/etc/os-release-host:ro -v /var/run:/var/run:ro -v /sys/fs/cgroup:/sys/fs/cgroup -v /var/run/docker.sock:/var/run/docker.sock'
DEFAULT_CONTAINER_NAME = 'tracee'
DEFAULT_LOGFILE = '/tmp/tracee_logs.log'

container_id = None
running = True


def show_version():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Tracee}")


def show_interfaces():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Tracee}")
    print("interface {value=tracee}{display=Tracee local capture}")


class ConfigArg:
    def __init__(self, number: int, call: str, display: str, type: str, **kwargs):
        self.number = number
        self.call = call
        self.display = display
        self.type = type
        self.kwargs = kwargs
    
    def __str__(self) -> str:
        string = 'arg {number=%d}{call=%s}{display=%s}{type=%s}' % (self.number, self.call, self.display, self.type)
        for arg, val in self.kwargs.items():
            string += '{%s=%s}' % (arg, str(val))
        
        return string


class ConfigVal:
    def __init__(self, arg: int, value: str, display: str, **kwargs):
        self.arg = arg
        self.value = value
        self.display = display
        self.kwargs = kwargs
    
    def __str__(self) -> str:
        string = 'value {arg=%d}{value=%s}{display=%s}' % (self.arg, self.value, self.display)
        for arg, val in self.kwargs.items():
            string += '{%s=%s}' % (arg, str(val))
        
        return string


def load_preset(preset: str) -> str:
    preset_file = os.path.join(os.path.dirname(__file__), 'tracee-capture', 'presets', preset)

    with open(preset_file, 'r') as f:
        return f.read().rstrip('\n').rstrip('\r')


def get_effective_tracee_options(args: argparse.Namespace) -> str:
    if args.preset is not None and args.preset != 'none':
        return load_preset(args.preset)
        
    #if settings.get('override_tracee_options'):
    return args.custom_tracee_options or ''


def get_presets() -> List[str]:
    presets_dir = os.path.join(os.path.dirname(__file__), 'tracee-capture', 'presets')
    os.makedirs(presets_dir, exist_ok=True)

    presets = []
    for filename in os.listdir(presets_dir):
        presets.append(filename)
    
    return presets


def show_config(reload_option: Optional[str]):
    presets = get_presets()

    args: List[ConfigArg] = [
        ConfigArg(number=0, call='--logfile', display='Tracee logs file', type='fileselect',
            default=DEFAULT_LOGFILE,
            group=GENERAL_GROUP
        ),
        ConfigArg(number=1, call='--image', display='Docker image', type='string',
            tooltip='Tracee docker image',
            required='true',
            default=DEFAULT_TRACEE_IMAGE,
            group=GENERAL_GROUP
        ),
        ConfigArg(number=2, call='--name', display='Container name', type='string',
            default=DEFAULT_CONTAINER_NAME,
            group=GENERAL_GROUP
        ),
        ConfigArg(number=3, call='--docker-options', display='Docker options', type='string',
            tooltip='Command line options for docker',
            default=DEFAULT_DOCKER_OPTIONS,
            group=GENERAL_GROUP
        ),
        """ConfigArg(number=4, call='--override-tracee-options', display='Override options', type='boolean',
            tooltip='Use custom tracee options',
            default='true' if settings.get('override_tracee_options') else 'false',
            group=TRACEE_OPTIONS_GROUP
        )""",
        ConfigArg(number=5, call='--custom-tracee-options', display='Custom tracee options', type='string',
            tooltip='Command line options for tracee',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(number=6, call='--preset', display='Preset', type='selector',
            tooltip='Tracee options preset',
            group=PRESET_GROUP,
            reload='true',
            placeholder='Reload presets'
        ),
        ConfigArg(number=7, call='--preset-file', display='Preset file', type='fileselect',
            group=PRESET_GROUP
        ),
        ConfigArg(number=8, call='--preset-from-file', display='Update preset from file', type='selector',
            tooltip='Update existing preset or create new preset from the above selected file',
            group=PRESET_GROUP,
            reload='true',
            placeholder='Update'
        ),
        ConfigArg(number=9, call='--delete-preset', display='Delete preset', type='selector',
            group=PRESET_GROUP,
            reload='true',
            placeholder='Delete'    
        )
    ]

    values: List[ConfigVal] = []

    if reload_option is None or reload_option == 'preset':
        values.append(ConfigVal(arg=6, value='none', display=f'No preset (use "{TRACEE_OPTIONS_GROUP}" tab)', default='true'))
        for preset in presets:
            values.append(ConfigVal(arg=6, value=preset, display=preset, default='false'))
    
    if reload_option is None or reload_option == 'preset-from-file':
        values.append(ConfigVal(arg=8, value='new', display='New preset (uses file name)', default='true'))
        for preset in presets:
            values.append(ConfigVal(arg=8, value=preset, display=preset, default='false'))
    
    if reload_option is None or reload_option == 'delete-preset':
        values.append(ConfigVal(arg=9, value='none', display='', default='true'))
        for preset in presets:
            values.append(ConfigVal(arg=9, value=preset, display=preset))

    if reload_option is None:
        for arg in args:
            print(str(arg))
    
    for val in values:
        print(str(val))


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
    logs_pipe_f = os.open(logs_pipe, os.O_RDONLY)
    fcntl.fcntl(logs_pipe_f, F_SETPIPE_SZ, TRACEE_OUTPUT_PIPE_CAPACITY)
    extcap_pipe_f = open(extcap_pipe, 'wb')

    # write fake PCAP header
    extcap_pipe_f.write(get_fake_pcap_header())

    # read events until the the capture stops
    while running:
        data = os.read(logs_pipe_f, TRACEE_OUTPUT_PIPE_CAPACITY)

        # split read data into individual events (TODO: this method might hurt perf, might want to search for newlines while reading)
        for event in data.split(b'\n'):
            if len(event) > 0:
                write_event(event, extcap_pipe_f)
        extcap_pipe_f.flush()
    
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

    os.remove(TRACEE_OUTPUT_PIPE)

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
    
    tracee_options = get_effective_tracee_options(args)
    
    # create pipe to get events from tracee
    if os.path.isdir(TRACEE_OUTPUT_PIPE):
        os.rmdir(TRACEE_OUTPUT_PIPE)
    else:
        try:
            os.remove(TRACEE_OUTPUT_PIPE)
        except FileNotFoundError:
            pass
    os.mkfifo(TRACEE_OUTPUT_PIPE)

    # create file to get logs from tracee
    if os.path.isdir(args.logfile):
        os.rmdir(args.logfile)
    open(args.logfile, 'w').close()

    reader_th = Thread(target=read_output, args=(TRACEE_OUTPUT_PIPE, args.fifo), daemon=True)
    reader_th.start()

    command = 'docker run -d'

    if len(args.name) > 0:
        command += f' --name {args.name}'
    
    command += f' {args.docker_options} -v {TRACEE_OUTPUT_PIPE}:/output.pipe:rw -v {args.logfile}:/logs.log:rw {args.image} {tracee_options}'

    # add exclusions that may spam the capture
    if "comm=" not in tracee_options: # make sure there is no comm filter in place, otherwise it will be overriden
        command += f" --scope comm!='{READER_COMM}' --scope comm!=tracee --scope comm!=wireshark --scope comm!=dumpcap"
    
    command += f" -o json:/output.pipe --log file:/logs.log"

    signal.signal(signal.SIGINT, stop_capture)
    signal.signal(signal.SIGTERM, stop_capture)
    
    proc = subp.Popen(['/bin/sh', '-c', command], stdout=subp.PIPE, stderr=subp.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        sys.stderr.write(f'docker run returned with error code {proc.returncode}, stderr dump:\n{err}')
        sys.exit(1)
    
    global container_id
    container_id = out.decode().rstrip('\n')

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


def handle_reload(option: str, args: argparse.Namespace):
    # copy selected file to presets dir
    if option == 'preset-from-file' and args.preset_file is not None:
        presets_dir = os.path.join(os.path.dirname(__file__), 'tracee-capture', 'presets')
        dst_file = args.preset_from_file if args.preset_from_file != 'new' else args.preset_file
        shutil.copyfile(args.preset_file, os.path.join(presets_dir, os.path.basename(dst_file)))
    
    elif option == 'delete-preset' and args.delete_preset is not None and args.delete_preset != 'none':
        preset_file = os.path.join(os.path.dirname(__file__), 'tracee-capture', 'presets', args.delete_preset)
        os.remove(preset_file)


def main():
    parser = argparse.ArgumentParser(prog=os.path.basename(__file__), description='Capture events and packets using Tracee')

    # extcap arguments
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")
    parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--capture", help="Start the capture routine", action="store_true")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
    parser.add_argument("--extcap-reload-option", help="Reload elements for the given option")

    # custom arguments
    parser.add_argument('--logfile', type=str, default=DEFAULT_LOGFILE)
    parser.add_argument('--image', type=str, default=DEFAULT_TRACEE_IMAGE)
    parser.add_argument('--name', type=str, default=DEFAULT_CONTAINER_NAME)
    parser.add_argument('--docker-options', type=str, default=DEFAULT_DOCKER_OPTIONS)
    #parser.add_argument('--override-tracee-options', type=str, default='true' if defaults.get('override_tracee_options') else 'false')
    parser.add_argument('--custom-tracee-options', type=str)
    parser.add_argument('--preset', type=str)
    parser.add_argument('--preset-file', type=str)
    parser.add_argument('--preset-from-file', type=str)
    parser.add_argument('--delete-preset', type=str)

    args = parser.parse_args()

    if args.extcap_version and not args.extcap_interfaces:
        show_version()
        sys.exit(0)

    if args.extcap_interfaces or args.extcap_interface is None:
        show_interfaces()
        sys.exit(0)
    
    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit("An interface must be provided or the selection must be displayed")
    
    """if not args.override_tracee_options:
        args.override_tracee_options = False
    else:
        args.override_tracee_options = True if args.override_tracee_options == 'true' else False"""
    
    if args.extcap_reload_option is not None:
        handle_reload(args.extcap_reload_option, args)
    
    if args.extcap_config:
        show_config(args.extcap_reload_option)
    elif args.extcap_dlts:
        show_dlts()
    elif args.capture:
        tracee_capture(args)
    
    sys.exit(0)


if __name__ == '__main__':
    #sys.stderr.write(f'{sys.argv}\n')
    main()
