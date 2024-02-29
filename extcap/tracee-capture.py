#!/usr/bin/env python3

from typing import Dict, List, NoReturn, Optional, Tuple

import argparse
from ctypes import cdll, byref, create_string_buffer
import fcntl
import json
import os
import select
import shutil
import signal
import socket
import struct
import subprocess as subp
import sys
from threading import Thread
from time import sleep


DLT_USER0 = 147
TRACEE_OUTPUT_PIPE = '/tmp/tracee_output.pipe'
TRACEE_OUTPUT_PIPE_CAPACITY = 262144 # enough to hold the largest event encountered so far
F_SETPIPE_SZ = 1031 # python < 3.10 does not have fcntl.F_SETPIPE_SZ
DATA_PORT = 4000
CTRL_PORT = 4001
READER_COMM = 'tracee-capture'
SSH_CTL_SOCK_DATA = '/tmp/sshctl_data.sock'
SSH_CTL_SOCK_CTRL = '/tmp/sshctl_ctrl.sock'
REMOTE_CAPTURE_SCRIPT_PATH = '/tmp/remote-capture.py'
REMOTE_CAPTURE_CONFIG_PATH = '/tmp/remote-config.json'

GENERAL_GROUP = 'General'
REMOTE_GROUP = 'Remote capture'
TRACEE_OPTIONS_GROUP = 'Tracee options'
PRESET_GROUP = 'Preset control'

DEFAULT_CAPTURE_TYPE = 'local'
DEFAULT_TRACEE_IMAGE = 'aquasec/tracee:latest'
DEFAULT_DOCKER_OPTIONS = '--pid=host --cgroupns=host --privileged -v /etc/os-release:/etc/os-release-host:ro -v /var/run:/var/run:ro -v /sys/fs/cgroup:/sys/fs/cgroup -v /var/run/docker.sock:/var/run/docker.sock'
DEFAULT_CONTAINER_NAME = 'tracee'
DEFAULT_LOGFILE = '/tmp/tracee_logs.log'


class SSHOptions:
    def __init__(self,
                 address: Optional[str],
                 port: int,
                 username: Optional[str],
                 password: Optional[str],
                 privkey: Optional[str],
                 passphrase: Optional[str],
                 host: Optional[str]):
        self.address = address
        self.port = port
        self.username = username
        self.password = password
        self.privkey = privkey
        self.passphrase = passphrase
        self.host = host

        if host is not None:
            if address is not None or username is not None or password is not None or privkey is not None or passphrase is not None:
                raise ValueError('invalid use of SSH host together with other options')

        else:
            if address is None:
                raise ValueError('no address specified')
            if username is None:
                raise ValueError('no username specified')
            if password is not None and privkey is not None:
                raise ValueError('invalid use of private key together with password')
            if password is not None and passphrase is not None:
                raise ValueError('invalid use of passphrase toghether with password')
    
    @property
    def options(self) -> str:
        ssh_opts = ''

        if self.privkey is not None:
            ssh_opts += f' -i {self.privkey}'
        
        if self.port != 22:
            ssh_opts += f' -p {self.port}'
        
        return ssh_opts
    
    @property
    def server(self) -> str:
        if self.host is not None:
            return self.host
        elif self.username is not None and self.address is not None:
            return f' {self.username}@{self.address}'
        else:
            raise ValueError()
    
    def __str__(self) -> str:
        ssh_opts = ''

        if self.privkey is not None:
            ssh_opts += f' -i {self.privkey}'
        
        if self.port != 22:
            ssh_opts += f' -p {self.port}'
        
        if self.username is not None and self.address is not None:
            ssh_opts += f' {self.username}@{self.address}'
        elif self.host is not None:
            ssh_opts += f' {self.host}'
        else:
            raise ValueError()
        
        return ssh_opts


container_id = None
running = True
reader_th = None
local = True
ssh_opts: SSHOptions = None


def show_version():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Tracee}")


def show_interfaces():
    print("extcap {version=1.0}{help=https://www.wireshark.org}{display=Tracee}")
    print("interface {value=tracee}{display=Tracee local capture}")


class ConfigArg:
    next_id: int = 0
    id_map: Dict[str, int] = {}

    def __init__(self, call: str, display: str, type: str, **kwargs):
        self.number = ConfigArg.next_id
        ConfigArg.next_id += 1
        self.call = call
        ConfigArg.id_map[self.call] = self.number
        self.display = display
        self.type = type
        self.kwargs = kwargs
    
    @classmethod
    def id_from_call(cls, call: str) -> int:
        return cls.id_map[call]
    
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
    
    # add custom options
    options = args.custom_tracee_options or ''

    # add container scope
    container_scope = None
    if args.container_scope == 'container':
        container_scope = 'container'
    elif args.container_scope == 'not-container':
        container_scope = 'not-container'
    elif args.container_scope == 'new-container':
        container_scope = 'container=new'
    
    if container_scope is not None:
        options += f' --scope {container_scope}'
    
    # add comm
    if args.comm is not None and len(args.comm) > 0:
        options += f' --scope comm="{args.comm}"'
    
    # add executable
    if args.exec is not None and len(args.exec) > 0:
        options += f' --scope executable="{args.exec}"'
    
    # add process scope
    if args.process_scope == 'new':
        options += ' --scope pid=new'
    elif args.process_scope == 'follow':
        options += ' --scope follow'

    # add event sets
    if args.event_sets is not None:
        options += f' --events {args.event_sets}'
    
    return options


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
        ConfigArg(call='--capture-type', display='Capture type', type='radio',
            tooltip='Where to capture (locally / remotely over SSH)',
            group=GENERAL_GROUP
        ),
        ConfigArg(call='--logfile', display='Tracee logs file', type='fileselect',
            default=DEFAULT_LOGFILE,
            group=GENERAL_GROUP
        ),
        ConfigArg(call='--container-image', display='Docker image', type='string',
            tooltip='Tracee docker image',
            default=DEFAULT_TRACEE_IMAGE,
            group=GENERAL_GROUP
        ),
        ConfigArg(call='--container-name', display='Container name', type='string',
            default=DEFAULT_CONTAINER_NAME,
            group=GENERAL_GROUP
        ),
        ConfigArg(call='--docker-options', display='Docker options', type='string',
            tooltip='Command line options for docker',
            default=DEFAULT_DOCKER_OPTIONS,
            group=GENERAL_GROUP
        ),
        ConfigArg(call='--remote-host', display='SSH server address', type='string',
            group=REMOTE_GROUP
        ),
        ConfigArg(call='--remote-port', display='SSH server port', type='long',
            validation='^\\d+$',
            default=22,
            group=REMOTE_GROUP
        ),
        ConfigArg(call='--ssh-username', display='SSH username', type='string',
            group=REMOTE_GROUP
        ),
        ConfigArg(call='--ssh-password', display='SSH password', type='password',
            group=REMOTE_GROUP
        ),
        ConfigArg(call='--ssh-privkey', display='SSH private key', type='fileselect',
            group=REMOTE_GROUP
        ),
        ConfigArg(call='--ssh-passphrase', display='SSH key passphrase', type='password',
            group=REMOTE_GROUP
        ),
        ConfigArg(call='--ssh-host', display='SSH saved host', type='string',
            tooltip='Host saved in the ~/.ssh/config file, assuming it contains all info needed for connecting',
            group=REMOTE_GROUP
        ),
        ConfigArg(call='--custom-tracee-options', display='Custom tracee options', type='string',
            tooltip='Command line options for tracee',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--container-scope', display='Container scope', type='radio',
            tooltip='Trace events from the selected scope of containers',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--comm', display='Process name', type='string',
            tooltip='Trace events from a specific process name',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--exec', display='Executable file', type='string',
            tooltip='Trace events from a specific executable file',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--process-scope', display='Process scope', type='radio',
            tooltip='Trace events from the selected scope of processes',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--event-sets', display='Event sets', type='multicheck',
            tooltip='Sets of events to trace',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--preset', display='Preset', type='selector',
            tooltip='Tracee options preset',
            group=PRESET_GROUP,
            reload='true',
            placeholder='Reload presets'
        ),
        ConfigArg(call='--preset-file', display='Preset file', type='fileselect',
            group=PRESET_GROUP
        ),
        ConfigArg(call='--preset-from-file', display='Update preset from file', type='selector',
            tooltip='Update existing preset or create new preset from the above selected file',
            group=PRESET_GROUP,
            reload='true',
            placeholder='Update'
        ),
        ConfigArg(call='--delete-preset', display='Delete preset', type='selector',
            group=PRESET_GROUP,
            reload='true',
            placeholder='Delete'    
        )
    ]

    id_capture_type = ConfigArg.id_from_call('--capture-type')
    id_container_scope = ConfigArg.id_from_call('--container-scope')
    id_process_scope = ConfigArg.id_from_call('--process-scope')
    id_event_sets = ConfigArg.id_from_call('--event-sets')
    id_preset = ConfigArg.id_from_call('--preset')
    id_preset_from_file = ConfigArg.id_from_call('--preset-from-file')
    id_delete_preset = ConfigArg.id_from_call('--delete-preset')

    values: List[ConfigVal] = [
        ConfigVal(arg=id_capture_type, value='local', display='Local', default='true'),
        ConfigVal(arg=id_capture_type, value='remote', display='Remote', default='false'),
        ConfigVal(arg=id_container_scope, value='all', display='All events', default='true'),
        ConfigVal(arg=id_container_scope, value='container', display='Events from containers', default='false'),
        ConfigVal(arg=id_container_scope, value='new-container', display='Events from new containers', default='false'),
        ConfigVal(arg=id_container_scope, value='not-container', display='Events from host', default='false'),
        ConfigVal(arg=id_process_scope, value='all', display='All processes', default='true'),
        ConfigVal(arg=id_process_scope, value='new', display='New processes'),
        ConfigVal(arg=id_process_scope, value='follow', display='Follow descendants (of specified process name or executable)'),
        ConfigVal(arg=id_event_sets, value='default', display='default', enabled='true'),
        ConfigVal(arg=id_event_sets, value='signatures', display='signatures', enabled='true'),
        ConfigVal(arg=id_event_sets, value='syscalls', display='syscalls', enabled='true'),
        ConfigVal(arg=id_event_sets, value='network_events', display='network_events', enabled='true'),
        ConfigVal(arg=id_event_sets, value='32bit_unique', display='32bit_unique', enabled='true', parent='syscalls'),
        ConfigVal(arg=id_event_sets, value='lsm_hooks', display='lsm_hooks', enabled='true'),
        ConfigVal(arg=id_event_sets, value='fs', display='fs', enabled='true'),
        ConfigVal(arg=id_event_sets, value='fs_read_write', display='fs_read_write', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_file_ops', display='fs_file_ops', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_dir_ops', display='fs_dir_ops', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_link_ops', display='fs_link_ops', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_fd_ops', display='fs_fd_ops', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_file_attr', display='fs_file_attr', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_mux_io', display='fs_mux_io', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_async_io', display='fs_async_io', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_sync', display='fs_sync', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_info', display='fs_info', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='fs_monitor', display='fs_monitor', enabled='true', parent='fs'),
        ConfigVal(arg=id_event_sets, value='proc', display='proc', enabled='true'),
        ConfigVal(arg=id_event_sets, value='proc_mem', display='proc_mem', enabled='true', parent='proc'),
        ConfigVal(arg=id_event_sets, value='proc_sched', display='proc_sched', enabled='true', parent='proc'),
        ConfigVal(arg=id_event_sets, value='proc_ids', display='proc_ids', enabled='true', parent='proc'),
        ConfigVal(arg=id_event_sets, value='proc_life', display='proc_life', enabled='true', parent='proc'),
        ConfigVal(arg=id_event_sets, value='signals', display='signals', enabled='true'),
        ConfigVal(arg=id_event_sets, value='ipc', display='ipc', enabled='true'),
        ConfigVal(arg=id_event_sets, value='ipc_pipe', display='ipc_pipe', enabled='true', parent='ipc'),
        ConfigVal(arg=id_event_sets, value='ipc_shm', display='ipc_shm', enabled='true', parent='ipc'),
        ConfigVal(arg=id_event_sets, value='ipc_sem', display='ipc_sem', enabled='true', parent='ipc'),
        ConfigVal(arg=id_event_sets, value='ipc_msgq', display='ipc_msgq', enabled='true', parent='ipc'),
        ConfigVal(arg=id_event_sets, value='ipc_futex', display='ipc_futex', enabled='true', parent='ipc'),
        ConfigVal(arg=id_event_sets, value='time', display='time', enabled='true'),
        ConfigVal(arg=id_event_sets, value='time_timer', display='time_timer', enabled='true', parent='time'),
        ConfigVal(arg=id_event_sets, value='time_tod', display='time_tod', enabled='true', parent='time'),
        ConfigVal(arg=id_event_sets, value='time_clock', display='time_clock', enabled='true', parent='time'),
        ConfigVal(arg=id_event_sets, value='net', display='net', enabled='true'),
        ConfigVal(arg=id_event_sets, value='net_sock', display='net_sock', enabled='true', parent='net'),
        ConfigVal(arg=id_event_sets, value='net_snd_rcv', display='net_snd_rcv', enabled='true', parent='net'),
        ConfigVal(arg=id_event_sets, value='flows', display='flows', enabled='true', parent='net'),
        ConfigVal(arg=id_event_sets, value='system', display='system', enabled='true'),
        ConfigVal(arg=id_event_sets, value='system_module', display='system_module', enabled='true', parent='system'),
        ConfigVal(arg=id_event_sets, value='system_numa', display='system_numa', enabled='true', parent='system'),
        ConfigVal(arg=id_event_sets, value='system_keys', display='system_keys', enabled='true', parent='system'),
        ConfigVal(arg=id_event_sets, value='container', display='container', enabled='true'),
        ConfigVal(arg=id_event_sets, value='derived', display='derived', enabled='true'),
        ConfigVal(arg=id_event_sets, value='security_alert', display='security_alert', enabled='true')
    ]

    if reload_option is None or reload_option == 'preset':
        values.append(ConfigVal(arg=id_preset, value='none', display=f'No preset (use "{TRACEE_OPTIONS_GROUP}" tab)', default='true'))
        for preset in presets:
            values.append(ConfigVal(arg=id_preset, value=preset, display=preset, default='false'))
    
    if reload_option is None or reload_option == 'preset-from-file':
        values.append(ConfigVal(arg=id_preset_from_file, value='new', display='New preset (uses file name)', default='true'))
        for preset in presets:
            values.append(ConfigVal(arg=id_preset_from_file, value=preset, display=preset, default='false'))
    
    if reload_option is None or reload_option == 'delete-preset':
        values.append(ConfigVal(arg=id_delete_preset, value='none', display='', default='true'))
        for preset in presets:
            values.append(ConfigVal(arg=id_delete_preset, value=preset, display=preset))

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


def recvall(conn: socket.socket, length: int):
    # helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


def recv_msg(conn: socket.socket):
    # read message length and unpack it into an integer
    raw_msglen = recvall(conn, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # read the message data
    return recvall(conn, msglen)


def read_output(extcap_pipe: str):
    global running

    # change our process name so we can exclude it (otherwise it may flood capture with pipe read activity)
    # TODO: using a PID is more robust, but currently there is no way to filter by PID in namespace (required when running on WSL)
    set_proc_name(READER_COMM)
    
    # open extcap pipe
    extcap_pipe_f = open(extcap_pipe, 'wb')

    # write fake PCAP header
    extcap_pipe_f.write(get_fake_pcap_header())

    if local:
        # open tracee output pipe
        tracee_output_pipe_f = os.open(TRACEE_OUTPUT_PIPE, os.O_RDONLY | os.O_NONBLOCK)
        fcntl.fcntl(tracee_output_pipe_f, F_SETPIPE_SZ, TRACEE_OUTPUT_PIPE_CAPACITY)
    
    else:
        # open tracee output socket and listen for an incoming connection
        tracee_output_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracee_output_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tracee_output_sock.bind(('127.0.0.1', DATA_PORT))
        tracee_output_sock.listen(0)
        tracee_output_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, TRACEE_OUTPUT_PIPE_CAPACITY)
        tracee_output_sock.settimeout(0.1)

        while running:
            try:
                tracee_output_conn, _ = tracee_output_sock.accept()
                break
            except socket.timeout:
                continue

    # read events until the the capture stops
    while running:
        if local:
            r, _, _ = select.select([ tracee_output_pipe_f ], [], [], 0.1)
            if tracee_output_pipe_f in r:
                data = os.read(tracee_output_pipe_f, TRACEE_OUTPUT_PIPE_CAPACITY)
            else:
                continue
        else:
            try:
                data = recv_msg(tracee_output_conn)
            except BrokenPipeError:
                break

        # split read data into individual events (TODO: this method might hurt perf, might want to search for newlines while reading)
        for event in data.split(b'\n'):
            if len(event) > 0:
                write_event(event, extcap_pipe_f)
        extcap_pipe_f.flush()
    
    if local:
        os.close(tracee_output_pipe_f)
    else:
        tracee_output_conn.close()
        tracee_output_sock.close()
    extcap_pipe_f.close()


def construct_ssh_options(args: argparse.Namespace):
    return SSHOptions(address=args.remote_host,
                        port=args.remote_port,
                        username=args.ssh_username,
                        password=args.ssh_password,
                        privkey=args.ssh_privkey,
                        passphrase=args.ssh_passphrase,
                        host=args.ssh_host)


def send_command(command: str) -> Tuple[bytes, bytes, int]:
    proc = subp.Popen(['/bin/sh', '-c', command], stdout=subp.PIPE, stderr=subp.PIPE)
    out, err = proc.communicate()
    return out, err, proc.returncode


def send_ssh_command(command: str, ssh_opts: SSHOptions) -> Tuple[bytes, bytes, int]:
    if not command.startswith('ssh ') and not command.startswith('scp '):
        raise ValueError(f'invalid SSH command "{command}"')
    
    if ssh_opts.password is not None:
        return send_command(f'sshpass -p {ssh_opts.password} {command}')
    elif ssh_opts.passphrase is not None:
        return send_command(f'sshpass -Ppassphrase -p {ssh_opts.passphrase} {command}')
    else:
        new_command = f'{command[:3]} -o BatchMode=yes {command[4:]}'
        return send_command(new_command)


def cleanup():
    global local, ssh_opts

    try:
        os.remove(TRACEE_OUTPUT_PIPE)
    except FileNotFoundError:
        pass

    try:
        os.remove(REMOTE_CAPTURE_CONFIG_PATH)
    except FileNotFoundError:
        pass

    if not local and ssh_opts is not None:
        # stop data SSH tunnel
        command = f'ssh -S {SSH_CTL_SOCK_DATA} -O exit {ssh_opts.server}'
        send_ssh_command(command, ssh_opts)
        try:
            os.remove(SSH_CTL_SOCK_DATA)
        except FileNotFoundError:
            pass
        
        # stop control SSH tunnel
        command = f'ssh -S {SSH_CTL_SOCK_CTRL} -O exit {ssh_opts.server}'
        send_ssh_command(command, ssh_opts)
        try:
            os.remove(SSH_CTL_SOCK_CTRL)
        except FileNotFoundError:
            pass

        # delete remote capture script
        command = f'ssh {ssh_opts} "rm {REMOTE_CAPTURE_SCRIPT_PATH}"'
        send_ssh_command(command, ssh_opts)

        # delete remote tracee logs file
        command = f'ssh {ssh_opts} "rm {DEFAULT_LOGFILE}"'
        send_ssh_command(command, ssh_opts)


def error(msg: str) -> NoReturn:
    global running
    running = False

    cleanup()

    sys.stderr.write(f'{msg}\n')
    sys.exit(1)


def stop_capture(signum, frame):
    global running, container_id, local, ssh_opts

    running = False

    if local:
        if container_id is None:
            cleanup()
            sys.exit(0)

        command = f'docker kill {container_id}'
        _, err, returncode = send_command(command)
        if returncode != 0:
            error(f'docker kill returned with error code {returncode}, stderr dump:\n{err}')


def capture_local(args: argparse.Namespace):
    global running

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

    # start reader thread
    global reader_th
    reader_th = Thread(target=read_output, args=(args.fifo,))
    reader_th.start()

    command = 'docker run -d'

    if len(args.container_name) > 0:
        command += f' --name {args.container_name}'
    
    command += f' {args.docker_options} -v {TRACEE_OUTPUT_PIPE}:/output.pipe:rw -v {args.logfile}:/logs.log:rw {args.container_image} {tracee_options}'

    # add exclusions that may spam the capture
    if 'comm=' not in tracee_options: # make sure there is no comm filter in place, otherwise it will be overriden
        command += f' --scope comm!="{READER_COMM}" --scope comm!=tracee --scope comm!=wireshark --scope comm!=dumpcap'
    
    command += f' -o json:/output.pipe --log file:/logs.log'

    out, err, returncode = send_command(command)
    if returncode != 0:
        error(f'docker run returned with error code {returncode}, stderr dump:\n{err}')
    
    global container_id
    container_id = out.decode().rstrip('\n')

    # wait until tracee exits (triggered by stop_capture or by an error)
    command = f'docker wait {container_id}'
    _, err, returncode = send_command(command)
    if returncode != 0:
        error(f'docker wait returned with error code {returncode}, stderr dump:\n{err}')
    
    running = False
    reader_th.join()
    
    # check tracee logs for errors
    command = f'docker logs {container_id}'
    _, logs_err, returncode = send_command(command)
    if returncode != 0:
        error(f'docker logs returned with error code {returncode}, stderr dump:\n{err}')
    
    # remove tracee container
    command = f'docker rm {container_id}'
    _, err, returncode = send_command(command)
    if returncode != 0:
        error(f'docker rm returned with error code {returncode}, stderr dump:\n{err}')
    
    if len(logs_err) > 0:
        error(f'Tracee exited with error message:\n{logs_err.decode()}')
    
    cleanup()


def control_worker():
    global running

    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ctrl_sock.settimeout(0.1) # don't block on accept forever in case remote capture script fails
    ctrl_sock.bind(('127.0.0.1', CTRL_PORT))
    ctrl_sock.listen(0)
    ctrl_conn = None

    while running:
        if ctrl_conn is None:
            try:
                ctrl_conn, _ = ctrl_sock.accept()
            except socket.timeout:
                continue
        
        sleep(0.1)
    
    # send termination signal to the remote capture
    if ctrl_conn is not None:
        ctrl_conn.send(b'stop')
        ctrl_conn.close()
    
    ctrl_sock.close()


def capture_remote(args: argparse.Namespace):
    global ssh_opts

    try:
        ssh_opts = construct_ssh_options(args)
    except ValueError as ex:
        error(str(ex))
    
    tracee_options = get_effective_tracee_options(args)

    # prepare ssh tunnel to receive output
    command = f'ssh -f -N -M -S {SSH_CTL_SOCK_DATA} -R {DATA_PORT}:localhost:{DATA_PORT} {ssh_opts}'
    _, err, returncode = send_ssh_command(command, ssh_opts)
    if returncode != 0:
        error(f'error setting up SSH tunnel:\n{err}')
    
    # prepare ssh tunnel for control
    command = f'ssh -f -N -M -S {SSH_CTL_SOCK_CTRL} -R {CTRL_PORT}:localhost:{CTRL_PORT} {ssh_opts}'
    _, err, returncode = send_ssh_command(command, ssh_opts)
    if returncode != 0:
        error(f'error setting up SSH tunnel:\n{err}')
    
    # copy remote capture script
    remote_capture_script = os.path.join(os.path.dirname(__file__), 'tracee-capture', 'remote-capture.py')
    command = f'scp {ssh_opts.options} {remote_capture_script} {ssh_opts.server}:{REMOTE_CAPTURE_SCRIPT_PATH}'
    _, err, returncode = send_ssh_command(command, ssh_opts)
    if returncode != 0:
        error(f'error copying capture script:\n{err}')
    
    command = f'ssh {ssh_opts} "chmod +x {REMOTE_CAPTURE_SCRIPT_PATH}"'
    _, err, returncode = send_ssh_command(command, ssh_opts)
    if returncode != 0:
        error(f'error setting remote capture script as executable:\n{err}')
    
    # create configuration and copy it
    config = {
        'data_port': DATA_PORT,
        'ctrl_port': CTRL_PORT,
        'container_name': args.container_name,
        'docker_options': args.docker_options,
        'container_image': args.container_image,
        'tracee_options': tracee_options
    }

    with open(REMOTE_CAPTURE_CONFIG_PATH, 'w') as f:
        f.write(json.dumps(config))
    
    command = f'scp {ssh_opts.options} {REMOTE_CAPTURE_CONFIG_PATH} {ssh_opts.server}:{REMOTE_CAPTURE_CONFIG_PATH}'
    _, err, returncode = send_ssh_command(command, ssh_opts)
    if returncode != 0:
        error(f'error copying capture config:\n{err}')
    
    # start reader thread
    global reader_th
    reader_th = Thread(target=read_output, args=(args.fifo,))
    reader_th.start()
    
    # start control worker
    control_th = Thread(target=control_worker)
    control_th.start()
    
    # run remote capture script (blocks until it exits)
    command = f'ssh {ssh_opts} "{REMOTE_CAPTURE_SCRIPT_PATH} {REMOTE_CAPTURE_CONFIG_PATH}"'
    _, err, returncode = send_ssh_command(command, ssh_opts)
    if returncode != 0:
        error(f'error running remote capture script:\n{err}')
    
    # wait for the worker threads to exit
    reader_th.join()
    control_th.join()
    
    # copy tracee logs file
    command = f'scp {ssh_opts}:{DEFAULT_LOGFILE} {args.logfile}'
    _, err, returncode = send_ssh_command(command, ssh_opts)
    if returncode != 0:
        error(f'error copying tracee logs:\n{err}')
    
    cleanup()


def tracee_capture(args: argparse.Namespace):
    global local

    if args.capture_type == 'local':
        local = True
    elif args.capture_type == 'remote':
        local = False
    else:
        error(f'invalid capture type "{args.capture_type}"')

    if not args.fifo:
        error('no output pipe provided')
    
    if not args.container_image or not args.docker_options:
        error('no image or docker options provided')
    
    # catch termination signals from wireshark
    signal.signal(signal.SIGINT, stop_capture)
    signal.signal(signal.SIGTERM, stop_capture)

    if local:
        capture_local(args)
    else:
        capture_remote(args)


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
    parser.add_argument('--capture-type', type=str, default=DEFAULT_CAPTURE_TYPE)
    parser.add_argument('--logfile', type=str, default=DEFAULT_LOGFILE)
    parser.add_argument('--container-image', type=str, default=DEFAULT_TRACEE_IMAGE)
    parser.add_argument('--container-name', type=str, default=DEFAULT_CONTAINER_NAME)
    parser.add_argument('--docker-options', type=str, default=DEFAULT_DOCKER_OPTIONS)
    parser.add_argument('--remote-host', type=str),
    parser.add_argument('--remote-port', type=int, default=22),
    parser.add_argument('--ssh-username', type=str)
    parser.add_argument('--ssh-password', type=str)
    parser.add_argument('--ssh-privkey', type=str)
    parser.add_argument('--ssh-passphrase', type=str)
    parser.add_argument('--ssh-host', type=str)
    parser.add_argument('--custom-tracee-options', type=str)
    parser.add_argument('--container-scope', type=str)
    parser.add_argument('--comm', type=str)
    parser.add_argument('--exec', type=str)
    parser.add_argument('--process-scope', type=str)
    parser.add_argument('--event-sets', type=str)
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
        parser.exit('An interface must be provided or the selection must be displayed')
    
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
