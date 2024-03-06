#!/usr/bin/env python3

from typing import Dict, List, NoReturn, Optional, Tuple

import argparse
from ctypes import cdll, byref, create_string_buffer
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

import msgpack
import paramiko

LINUX = sys.platform.startswith('linux')
WINDOWS = os.name == 'nt'
MAC = sys.platform == 'darwin'


if WINDOWS:
    APPDATA = os.getenv('APPDATA')
    TMP_DIR = os.path.join(APPDATA, 'Traceeshark')

else:
    TMP_DIR = '/tmp/traceeshark'
    os.makedirs(TMP_DIR, exist_ok=True)


EXTCAP_VERSION = '0.2.0'
DLT_USER0 = 147
TRACEE_OUTPUT_BUF_CAPACITY = 262144 # enough to hold the largest event encountered so far
DATA_PORT = 4000
REMOTE_CAPTURE_LOGFILE = '/tmp/tracee_logs.log'
READER_COMM = 'tracee-capture'

GENERAL_GROUP = 'General'
REMOTE_GROUP = 'Remote capture'
TRACEE_OPTIONS_GROUP = 'Tracee options'
PRESET_GROUP = 'Preset control'

DEFAULT_CAPTURE_TYPE = 'local'
DEFAULT_TRACEE_IMAGE = 'aquasec/tracee:latest'
DEFAULT_DOCKER_OPTIONS = '--pid=host --cgroupns=host --privileged -v /etc/os-release:/etc/os-release-host:ro -v /var/run:/var/run:ro -v /sys/fs/cgroup:/sys/fs/cgroup -v /var/run/docker.sock:/var/run/docker.sock'
DEFAULT_CONTAINER_NAME = 'tracee'
DEFAULT_LOGFILE = os.path.join(TMP_DIR, 'tracee_logs.log')


args: argparse.Namespace = None
container_id: str = None
running: bool = True
local: bool = True
stopping: bool = False


def show_version():
    print("extcap {version=%s}{help=https://www.wireshark.org}{display=Tracee}" % EXTCAP_VERSION)


def show_interfaces():
    print("extcap {version=%s}{help=https://www.wireshark.org}{display=Tracee}" % EXTCAP_VERSION)
    print("interface {value=tracee}{display=Tracee capture}")


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


def ssh_connect(args: argparse.Namespace) -> paramiko.SSHClient:
    ssh_client = paramiko.SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy())

    try:
        ssh_client.connect(
            hostname=args.remote_host,
            port=args.remote_port,
            username=args.ssh_username,
            password=args.ssh_password,
            key_filename=args.ssh_privkey,
            passphrase=args.ssh_passphrase
        )
    
    except paramiko.SSHException as ex:
        error(str(ex))
    
    # there is a bug where paramiko tries to interpret an RSA key as a DSS key,
    # this only seems to happen when the key is invalid for this connection
    except ValueError:
        error('cannot authenticate using this private key')

    return ssh_client


def stop_capture(is_error: bool = False):
    global running, container_id, local, args, stopping

    if stopping:
        return
    
    stopping = True
    running = False

    if container_id is not None:
        ssh_client = None
        if not local:
            ssh_client = ssh_connect(args)
        
        command = f'docker kill {container_id}'
        _, err, returncode = send_command(local, command, ssh_client)
        if returncode != 0:
            error(f'docker kill returned with error code {returncode}, stderr dump:\n{err}\n')
        
        # an error occurred so we assume the main thread is not functioning, remove the container here
        if is_error:
            command = f'docker rm {container_id}'
            _, err, returncode = send_command(local, command, ssh_client)
            if returncode != 0:
                error(f'docker rm returned with error code {returncode}, stderr dump:\n{err}\n')

            # set this so if the main thread is still functioning,
            # it will not try to read the container's logs and remove it
            container_id = None


def read_output(extcap_pipe: str):
    global running, local

    # change our process name so we can exclude it (otherwise it may flood capture with pipe read activity)
    # TODO: using a PID is more robust, but currently there is no way to filter by PID in namespace (required when running on WSL)
    if local and LINUX:
        set_proc_name(READER_COMM)
    
    # create msgpack unpacker
    unpacker = msgpack.Unpacker(raw=True)
    
    # open extcap pipe
    extcap_pipe_f = open(extcap_pipe, 'wb')

    # write fake PCAP header
    extcap_pipe_f.write(get_fake_pcap_header())
    
    # open tracee output socket and listen for an incoming connection
    tracee_output_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tracee_output_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tracee_output_sock.bind(('127.0.0.1', DATA_PORT))
    tracee_output_sock.listen(0)
    tracee_output_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, TRACEE_OUTPUT_BUF_CAPACITY)
    tracee_output_sock.settimeout(0.1)

    tracee_output_conn = None
    while running:
        try:
            tracee_output_conn, _ = tracee_output_sock.accept()
            tracee_output_conn.settimeout(0.1)
            break
        except socket.timeout:
            continue

    # read events until the the capture stops
    while running:
        try:
            # read data and feed it to the unpacker
            data = tracee_output_conn.recv(TRACEE_OUTPUT_BUF_CAPACITY)
            unpacker.feed(data)
        except socket.timeout:
            continue
        except BrokenPipeError:
            break

        # unpack any ready events and write them to wireshark's pipe
        for entry in unpacker:
            write_event(entry[2][b'event'], extcap_pipe_f)
        try:
            extcap_pipe_f.flush()
        # on windows wireshark does not stop the capture gracefully, so we detect that the capture has stopped when the wireshark pipe breaks
        except OSError:
            stop_capture()
            break
    
    if tracee_output_conn is not None:
        tracee_output_conn.close()
    tracee_output_sock.close()
    try:
        extcap_pipe_f.close()
    except OSError:
        pass


def send_local_command(command: str) -> Tuple[str, str, int]:
    if WINDOWS:
        proc = subp.Popen(['cmd.exe', '/C', command], stdout=subp.PIPE, stderr=subp.PIPE)
    else:
        proc = subp.Popen(['/bin/sh', '-c', command], stdout=subp.PIPE, stderr=subp.PIPE)
    out, err = proc.communicate()
    return out.decode(), err.decode(), proc.returncode


def send_ssh_command(client: paramiko.SSHClient, command: str) -> Tuple[str, str, int]:
    _, stdout, stderr = client.exec_command(command)

    stdout_lines = stdout.readlines() # this waits until command finishes
    stderr_lines = stderr.readlines()

    return ''.join(stdout_lines), ''.join(stderr_lines), stdout.channel.recv_exit_status()


def send_command(local: bool, command: str, ssh_client: paramiko.SSHClient = None) -> Tuple[str, str, int]:
    if local:
        return send_local_command(command)
    
    if ssh_client is None:
        raise ValueError()
    
    return send_ssh_command(ssh_client, command)


def error(msg: str) -> NoReturn:
    sys.stderr.write(f'{msg}\n')
    stop_capture(is_error=True)
    raise RuntimeError()


def exit_cb(_signum, _frame):
    stop_capture(is_error=False)


def build_docker_run_command(args: argparse.Namespace, local: bool) -> str:
    tracee_options = get_effective_tracee_options(args)

    command = 'docker run -d'

    # when not using docker for Windows or Mac, we connect tracee to the local network
    if not local or (local and LINUX):
        command += f' --network=host'
        data_addr = '127.0.0.1'
    # when using docker for Windows or Mac, we connect back to the built-in host dns
    else:
        data_addr = 'host.docker.internal'

    if len(args.container_name) > 0:
        command += f' --name {args.container_name}'
    
    logfile = args.logfile if local else REMOTE_CAPTURE_LOGFILE
    command += f' {args.docker_options} -v {logfile}:/logs.log:rw {args.container_image} {tracee_options}'

    # add exclusions that may spam the capture
    if 'comm=' not in tracee_options: # make sure there is no comm filter in place, otherwise it will be overriden
        command += f' --scope comm!=tracee'

        # these exclusions are needed only when Wireshark is running on the same host that is being recorded
        if local and LINUX:
            command += f' --scope comm!="{READER_COMM}" --scope comm!=wireshark --scope comm!=dumpcap'
    
    command += f' --output forward:tcp://{data_addr}:{DATA_PORT} --log file:/logs.log'

    return command


def handle_connection(transport: paramiko.Transport, dst_addr: str, dst_port: int):
    # wait for incoming connection
    channel = transport.accept(None)

    # connect to the tunnel's receiving end
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((dst_addr, dst_port))
    except ConnectionRefusedError:
        sys.stderr.write(f'could not connect to {(dst_addr, dst_port)}\n')
        return
    
    while True:
        r, _, _ = select.select([sock, channel], [], [])
        if sock in r:
            try:
                data = sock.recv(1024)
                if len(data) == 0:
                    break
                channel.send(data)
            except ConnectionResetError:
                break
        if channel in r:
            try:
                data = channel.recv(1024)
                if len(data) == 0:
                    break
                sock.send(data)
            except ConnectionResetError:
                break
    
    channel.close()
    sock.close()


def prepare_local_capture(args: argparse.Namespace):
    # create file to get logs from tracee
    if os.path.isdir(args.logfile):
        os.rmdir(args.logfile)
    open(args.logfile, 'w').close()


def prepare_remote_capture(args: argparse.Namespace, ssh_client: paramiko.SSHClient):
    # prepare ssh tunnel to receive output
    ssh_data_client = ssh_connect(args)

    # on Windows, the previous capture doesn't terminate before the current one when restarting the capture,
    # so we have to wait a bit to give the previous capture a chance to clean up its forwarded ports
    for _ in range(10):
        try:
            ssh_data_client.get_transport().request_port_forward('127.0.0.1', DATA_PORT)
        except paramiko.SSHException as ex:
            # not Windows - this failure is not because of a previous capture that is in the process of stopping
            if not WINDOWS:
                error(str(ex))
            
            if 'TCP forwarding request denied' in str(ex):
                # retry in 1 second
                sleep(1)
            # unrelated error
            else:
                error(str(ex))
        else:
            break
    
    ssh_data_forwarder = Thread(
        target=handle_connection,
        args=(ssh_data_client.get_transport(), '127.0.0.1', DATA_PORT),
        daemon=True
    )
    ssh_data_forwarder.start()

    # create empty tracee logs file to be mounted into the tracee container
    # (this is necessary because if it doesn't exist, docker will assume it needs to be a directory)
    _, err, returncode = send_ssh_command(ssh_client, f'rm -rf {REMOTE_CAPTURE_LOGFILE} && touch {REMOTE_CAPTURE_LOGFILE}')
    if returncode != 0:
        error(f'error creating file for tracee logs, stderr dump:\n{err}')


def tracee_capture(args: argparse.Namespace):
    global local, running, container_id

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
    
    # catch termination signals from Wireshark (currently on Windows it is not possible to be notified of
    # termination, as a workaround we monitor Wireshark's pipe breaking in the reader thread as a sign of termination)
    signal.signal(signal.SIGINT, exit_cb)
    signal.signal(signal.SIGTERM, exit_cb)

    if local:
        ssh_client = None
        prepare_local_capture(args)
    else:
        ssh_client = ssh_connect(args)
        prepare_remote_capture(args, ssh_client)

    # start reader thread
    reader_th = Thread(target=read_output, args=(args.fifo,))
    reader_th.start()

    # run tracee container
    command = build_docker_run_command(args, local)
    out, err, returncode = send_command(local, command, ssh_client)
    if returncode != 0:
        error(f'docker run returned with error code {returncode}, stderr dump:\n{err}')
    container_id = out.rstrip('\n')

    # wait until tracee exits (triggered by stop_capture or by an error)
    command = f'docker wait {container_id}'
    _, err, returncode = send_command(local, command, ssh_client)
    if returncode != 0:
        error(f'docker wait returned with error code {returncode}, stderr dump:\n{err}')
    
    running = False

    # copy tracee logs file
    if not local:
        sftp_client = ssh_client.open_sftp()
        sftp_client.get(REMOTE_CAPTURE_LOGFILE, args.logfile)
        send_ssh_command(ssh_client, f'rm {REMOTE_CAPTURE_LOGFILE}')
    
    # the capture has been stopped because of an error condition,
    # so the stop_capture function already removed the container
    if container_id is None:
        return
    
    # check tracee logs for errors
    command = f'docker logs {container_id}'
    _, logs_err, returncode = send_command(local, command, ssh_client)
    if returncode != 0:
        error(f'docker logs returned with error code {returncode}, stderr dump:\n{err}')
    
    # remove tracee container
    command = f'docker rm {container_id}'
    _, err, returncode = send_command(local, command, ssh_client)
    if returncode != 0:
        error(f'docker rm returned with error code {returncode}, stderr dump:\n{err}')
    
    if len(logs_err) > 0:
        error(f'Tracee exited with error message:\n{logs_err.decode()}')


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
    global args

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
    #sys.stderr = open(os.path.join(TMP_DIR, 'capture_stderr.log'), 'w')
    try:
        main()
    # RuntimeError is raised by the error() function which already printed
    # an error message, don't raise it so the error screen is not cluttered
    except RuntimeError:
        stop_capture(is_error=True)
    # any other exception needs to be raised
    except Exception:
        stop_capture(is_error=True)
        raise
