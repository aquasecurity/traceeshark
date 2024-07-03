#!/usr/bin/env python3

from typing import BinaryIO, Dict, Iterator, List, NoReturn, Optional, Tuple

import argparse
from ctypes import cdll, byref, create_string_buffer
import os
from select import select
import shutil
import signal
import socket
import stat
import struct
import subprocess as subp
import sys
from threading import Lock, Thread
from time import sleep

import msgpack
import paramiko
import pcapng


LINUX = sys.platform.startswith('linux')
WINDOWS = os.name == 'nt'
MAC = sys.platform == 'darwin'

if WINDOWS:
    TMP_DIR = os.path.join(os.getenv('APPDATA'), 'Traceeshark')
else:
    TMP_DIR = '/tmp/traceeshark'
os.makedirs(TMP_DIR, exist_ok=True)

EXTCAP_VERSION = 'VERSION_PLACEHOLDER'
DLT_NULL = 0
DLT_USER0 = 147
TRACEE_OUTPUT_BUF_CAPACITY = 262144 # enough to hold the largest event encountered so far
DATA_PORT = 4000
REMOTE_CAPTURE_LOGFILE = '/tmp/tracee_logs.log'
REMOTE_CAPTURE_OUTPUT_DIR = '/tmp/tracee_output'
REMOTE_CAPTURE_NEW_ENTRYPOINT = '/tmp/new-entrypoint.sh'
READER_COMM = 'tracee-capture'

GENERAL_GROUP = 'General'
REMOTE_GROUP = 'Remote capture'
TRACEE_OPTIONS_GROUP = 'Tracee options'

DEFAULT_CAPTURE_TYPE = 'local'
DEFAULT_TRACEE_IMAGE = 'aquasec/tracee:latest'
DEFAULT_DOCKER_OPTIONS = '--pid=host --cgroupns=host --privileged -v /etc/os-release:/etc/os-release-host:ro -v /var/run:/var/run:ro -v /sys/fs/cgroup:/sys/fs/cgroup -v /var/run/docker.sock:/var/run/docker.sock'
DEFAULT_CONTAINER_NAME = 'traceeshark'
DEFAULT_LOGFILE = os.path.join(TMP_DIR, 'tracee_logs.log')
DEFAULT_OUTPUT_DIR = os.path.join(TMP_DIR, 'tracee_output')
DEFAULT_SNAPLEN = 'default'
DEFAULT_PACKET_INJECTION_INTERVAL = 30

# corresponds to "enum InterfaceControlCommand" from wireshark/ui/qt/interface_toolbar.cpp
CTRL_CMD_INITIALIZED = 0
CTRL_CMD_SET         = 1
CTRL_CMD_ADD         = 2
CTRL_CMD_REMOVE      = 3
CTRL_CMD_ENABLE      = 4
CTRL_CMD_DISABLE     = 5
CTRL_CMD_STATUSBAR   = 6
CTRL_CMD_INFORMATION = 7
CTRL_CMD_WARNING     = 8
CTRL_CMD_ERROR       = 9

# corresponds to the toolbar buttons, 0 is reserved for sending CTRL_CMD_INITIALIZED
CTRL_ARG_STOP           = 1
CTRL_ARG_COPY_ON_STOP   = 2
CTRL_ARG_INJECT_PACKETS_ON_STOP = 3
CTRL_ARG_COPY_OUTPUT    = 4
CTRL_ARG_INJECT_PACKETS = 5


args: argparse.Namespace = None
container_id: str = None
running: bool = True
local: bool = True
stopping: bool = False
copy_output: bool = False
inject_packets: bool = False
control_output_manager: 'ControlOutputManager' = None


def show_version():
    print("extcap {version=%s}{help=https://www.wireshark.org}{display=Tracee}" % EXTCAP_VERSION)


def show_interfaces():
    print("extcap {version=%s}{help=https://www.wireshark.org}{display=Tracee}" % EXTCAP_VERSION)
    print("interface {value=tracee}{display=Tracee capture}")
    print("control {number=%d}{type=button}{display=Stop}{tooltip=Stop the capture}" % CTRL_ARG_STOP)
    print("control {number=%d}{type=boolean}{display=Copy output on stop}{default=true}{tooltip=Copy output folder when stopping the capture}" % CTRL_ARG_COPY_ON_STOP)
    print("control {number=%d}{type=boolean}{display=Inject packets on stop}{default=true}{tooltip=Inject packets when stopping the capture}" % CTRL_ARG_INJECT_PACKETS_ON_STOP)
    print("control {number=%d}{type=button}{display=Copy output}{tooltip=Copy output folder from remote}" % CTRL_ARG_COPY_OUTPUT)
    print("control {number=%d}{type=button}{display=Inject packets}{tooltip=Inject packets captured by Tracee into the capture stream}" % CTRL_ARG_INJECT_PACKETS)


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
    options = ''

    if args.preset_file is not None:
        options += load_preset(args.preset_file)
    elif args.preset is not None and args.preset != 'none':
        options += load_preset(args.preset)
    
    # add custom options
    if args.custom_tracee_options:
        options += f' {args.custom_tracee_options}'

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
    
    # add artifacts to capture
    network = False
    network_captures = []

    if args.capture_artifacts is not None:
        for artifact in args.capture_artifacts.split(','):
            if 'network' not in artifact:
                options += f' --capture {artifact}'
            else:
                if not network:
                    options += f' --capture network'
                    network = True
                if artifact == 'network-single':
                    network_captures.append('single')
                elif artifact == 'network-per-process':
                    network_captures.append('process')
                elif artifact == 'network-per-command':
                    network_captures.append('command')
                elif artifact == 'network-per-container':
                    network_captures.append('container')
                
        if network:
            options += f' --capture pcap:{",".join(network_captures)} --capture pcap-snaplen:{args.network_snaplen}'
            if args.network_filtered:
                options += ' --capture pcap-options:filtered'
    
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
        ConfigArg(call='--output-dir', display='Tracee output folder', type='string',
            default=DEFAULT_OUTPUT_DIR,
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
        ConfigArg(call='--preset', display='Preset', type='selector',
            tooltip='Tracee options preset',
            group=TRACEE_OPTIONS_GROUP,
            reload='true',
            placeholder='Reload presets'
        ),
        ConfigArg(call='--preset-file', display='Preset file', type='fileselect',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--custom-tracee-options', display='Custom Tracee options', type='string',
            tooltip='Command line options for Tracee',
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
        ConfigArg(call='--capture-artifacts', display='Capture artifacts', type='multicheck',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--network-filtered', display='Filter network capture', type='boolflag',
            tooltip='Capture packets according to the selected scope',
            default='false',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--network-snaplen', display='Packet snaplen', type='string',
            validation='^(default|headers|max|\\d+(b|kb))$',
            default=DEFAULT_SNAPLEN,
            tooltip='Length of captured packets. See the "Forensics" section of Tracee\'s documentation for details',
            group=TRACEE_OPTIONS_GROUP
        ),
        ConfigArg(call='--packet-injection-interval', display='Packet injection interval', type='integer',
            default=DEFAULT_PACKET_INJECTION_INTERVAL,
            tooltip='If capturing packets, inject them into the event stream at an interval given in seconds, or 0 for no packet injection',
            group=TRACEE_OPTIONS_GROUP
        ),
    ]

    id_capture_type = ConfigArg.id_from_call('--capture-type')
    id_container_scope = ConfigArg.id_from_call('--container-scope')
    id_process_scope = ConfigArg.id_from_call('--process-scope')
    id_event_sets = ConfigArg.id_from_call('--event-sets')
    id_capture = ConfigArg.id_from_call('--capture-artifacts')
    id_preset = ConfigArg.id_from_call('--preset')

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
        ConfigVal(arg=id_event_sets, value='security_alert', display='security_alert', enabled='true'),
        ConfigVal(arg=id_capture, value='exec', display='Executable files', enabled='true'),
        ConfigVal(arg=id_capture, value='module', display='Kernel modules', enabled='true'),
        ConfigVal(arg=id_capture, value='bpf', display='eBPF programs', enabled='true'),
        ConfigVal(arg=id_capture, value='mem', display='Memory regions (mem_prot_alert)', enabled='true'),
        ConfigVal(arg=id_capture, value='network', display='Network packets', enabled='false'),
        ConfigVal(arg=id_capture, value='network-single', display='Single pcap', enabled='true', parent='network'),
        ConfigVal(arg=id_capture, value='network-per-process', display='Per process', enabled='true', parent='network'),
        ConfigVal(arg=id_capture, value='network-per-command', display='Per command', enabled='true', parent='network'),
        ConfigVal(arg=id_capture, value='network-per-container', display='Per container', enabled='true', parent='network')
    ]

    if reload_option is None or reload_option == 'preset':
        values.append(ConfigVal(arg=id_preset, value='none', display=f'No preset', default='false'))
        for preset in presets:
            values.append(ConfigVal(arg=id_preset, value=preset, display=preset, default='true' if preset == 'Default' else 'false'))

    if reload_option is None:
        for arg in args:
            print(str(arg))
    
    for val in values:
        print(str(val))


def show_dlts():
    print("dlt {number=%d}{name=USER0}{display=Tracee event}" % DLT_USER0)
    print("dlt {number=%d}{name=NULL}{display=Tracee packet}" % DLT_NULL)


class DataOutputManager:
    def __init__(self, extcap_pipe: str):
        # Initialize the pcapng file that is written to Wireshark's pipe.
        # Any access to the pipe and writer must be guarded by the lock.
        self._lock = Lock()
        self._extcap_pipe_f = open(extcap_pipe, 'wb')
        self._writer = self._init_pcapng()
    
    def write_block(self, block: pcapng.blocks.SectionMemberBlock):
        with self._lock:
            self._writer.write_block(block)
            self._extcap_pipe_f.flush()
    
    def write_event(self, event: bytes):
        ts = self._parse_ts(event)

        with self._lock:
            epb = self._writer.current_section.new_member(
                pcapng.blocks.EnhancedPacket,
                timestamp_high = ts >> 32,
                timestamp_low = ts & 0xffffffff,
                packet_len = len(event),
                packet_data = event
            )
        
        self.write_block(epb)
    
    def get_current_section(self) -> pcapng.blocks.SectionHeader:
        with self._lock:
            return self._writer.current_section
    
    def register_interface(self, interface: pcapng.blocks.InterfaceDescription):
        with self._lock:
            self._writer.current_section.register_interface(interface)
    
    def _init_pcapng(self) -> pcapng.FileWriter:
        shb = pcapng.blocks.SectionHeader()

        # create interface description for events
        shb.new_member(
            pcapng.blocks.InterfaceDescription,
            link_type=DLT_USER0,
            options={
                "if_name": "tracee",
                "if_description": "Tracee event",
                "if_tsresol": pcapng.utils.pack_timestamp_resolution(10, 9) # nanoseconds
            }
        )

        with self._lock:
            writer = pcapng.FileWriter(self._extcap_pipe_f, shb)
            self._extcap_pipe_f.flush()
            return writer
    
    def _parse_ts(self, event: bytes) -> int:
        if not event.startswith(b'{"timestamp":'):
            raise ValueError(f'invalid event: {event}')
        
        # skip {"timestamp": in the beginning of the event
        return int(event[13: event.find(b',')])


def set_proc_name(newname: str):
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(newname)+1)
    buff.value = newname.encode()
    libc.prctl(15, byref(buff), 0, 0, 0)


def ssh_connect(args: argparse.Namespace) -> paramiko.SSHClient:
    ssh_client = paramiko.SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())

    try:
        ssh_client.connect(
            hostname=args.remote_host,
            port=args.remote_port,
            username=args.ssh_username,
            password=args.ssh_password,
            key_filename=args.ssh_privkey,
            passphrase=args.ssh_passphrase,
            timeout=10
        )
    
    except paramiko.SSHException as ex:
        error(str(ex))
    
    except TimeoutError:
        error('SSH connection timed out')
    
    # there is a bug where paramiko tries to interpret an RSA key as a DSS key,
    # this only seems to happen when the key is invalid for this connection
    except ValueError:
        error('cannot authenticate using this private key')

    return ssh_client


def stop_capture(is_error: bool = False):
    global running, container_id, local, args, stopping, control_output_manager

    if stopping:
        return
    
    stopping = True
    running = False

    if container_id is not None:
        ssh_client = None
        if not local:
            ssh_client = ssh_connect(args)
        
        command = f'docker stop {container_id}'
        _, err, returncode = send_command(local, command, ssh_client)
        if returncode != 0 and 'No such container' not in err and 'is not running' not in err:
            error(f'docker stop returned with error code {returncode}, stderr dump:\n{err}\n')
        
        # an error occurred so we assume the main thread is not functioning, remove the container here
        if is_error:
            command = f'docker rm {container_id}'
            _, err, returncode = send_command(local, command, ssh_client)
            if returncode != 0 and 'No such container' not in err:
                error(f'docker rm returned with error code {returncode}, stderr dump:\n{err}\n')

            # set this so if the main thread is still functioning,
            # it will not try to read the container's logs and remove it
            container_id = None


def read_output(data_output_manager: DataOutputManager):
    global running, local

    # change our process name so we can exclude it (otherwise it may flood capture with pipe read activity)
    # TODO: using a PID is more robust, but currently there is no way to filter by PID in namespace (required when running on WSL)
    if local and LINUX:
        set_proc_name(READER_COMM)
    
    # create msgpack unpacker
    unpacker = msgpack.Unpacker(raw=True)
    
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
            try:
                data_output_manager.write_event(entry[2][b'event'])
            # on Windows Wireshark does not stop the capture gracefully, so we detect that the capture has stopped when the Wireshark pipe breaks
            except OSError:
                stop_capture()
                break
    
    if tracee_output_conn is not None:
        tracee_output_conn.close()
    tracee_output_sock.close()


def reader_thread(data_output_manager: DataOutputManager):
    try:
        read_output(data_output_manager)
    except Exception:
        stop_capture(is_error=True)
        raise


class SFTPManager:
    def __init__(self, sftp_client: paramiko.SFTPClient):
        self._sftp_client = sftp_client
        self._lock = Lock()
    
    def copy_dir_from_remote(self, remote_dir: str, local_dir: str) -> Iterator[str]:
        os.makedirs(local_dir, exist_ok=True)

        for filename in self.listdir(remote_dir):
            if stat.S_ISDIR(self.stat(f'{remote_dir}/{filename}').st_mode):
                yield from self.copy_dir_from_remote(f'{remote_dir}/{filename}', os.path.join(local_dir, filename))
            else:
                yield f'{remote_dir}/{filename}'
                self.get(f'{remote_dir}/{filename}', os.path.join(local_dir, filename))
    
    def get(self, remotepath: str, localpath: str, prefetch=True, max_concurrent_prefetch_requests=None):
        """
        Custom implementation of SFTPClient.get(), where the file size obtained from stat()
        is enforced so that a growing file does not get copied indefinitely.
        """
        size_copied = 0

        with open(localpath, 'wb') as fl:
            with self._lock:
                file_size = self._sftp_client.stat(remotepath).st_size
                with self._sftp_client.open(remotepath, 'rb') as fr:
                    if prefetch:
                        fr.prefetch(file_size, max_concurrent_prefetch_requests)
                    
                    while size_copied < file_size:
                        data = fr.read(min(32768, file_size - size_copied))
                        fl.write(data)
                        size_copied += len(data)
                        if len(data) == 0:
                            break

        s = os.stat(localpath)
        if s.st_size != size_copied:
            raise IOError(
                "size mismatch in get!  {} != {}".format(s.st_size, size_copied)
            )
    
    def listdir(self, *args, **kwargs):
        with self._lock:
            return self._sftp_client.listdir(*args, **kwargs)
    
    def stat(self, *args, **kwargs):
        with self._lock:
            return self._sftp_client.stat(*args, **kwargs)
    
    def put(self, *args, **kwargs):
        with self._lock:
            return self._sftp_client.put(*args, **kwargs)
    
    def remove(self, *args, **kwargs):
        with self._lock:
            return self._sftp_client.remove(*args, **kwargs)
    
    def isdir(self, s):
        """Return true if the pathname refers to an existing directory.
        Taken from os.path.isdir().
        """
        try:
            st = self.stat(s)
        except (OSError, ValueError):
            return False
        return stat.S_ISDIR(st.st_mode)
    
    def exists(self, path):
        """Test whether a path exists.  Returns False for broken symbolic links.
        Taken from is.path.exists().
        """
        try:
            self.stat(path)
        except (OSError, ValueError):
            return False
        return True


class PacketInjector:
    CURRENT_IFACE_ID: int = 1 # start from 1, as interface id 0 is reserved for the events interface

    def __init__(self, data_output_manager: DataOutputManager, sftp: SFTPManager, output_dir: str):
        self.data_output_manager = data_output_manager
        self.sftp = sftp
        self.output_dir = output_dir
        self._lock = Lock()

        # map of pcap file name (path) to a tuple containing the interface id and the last timestamp encountered
        self.file_state: Dict[str, Tuple[int, int]] = {}
    
    def inject_packets(self, queue: bool = False) -> Iterator[str]:
        # if a packet injection is already in progress, just do nothing
        available = self._lock.acquire(blocking=queue)
        if not available:
            return
        
        try:
            yield from self._inject_packets()
        finally:
            self._lock.release()
    
    def _inject_packets(self) -> Iterator[str]:
        global local

        if local:
            output_dir = self.output_dir
            isdir = os.path.isdir
            exists = os.path.exists
            listdir = os.listdir
            inject_packets_from_pcap = self._inject_packets_from_local_pcap
        else:
            output_dir = REMOTE_CAPTURE_OUTPUT_DIR
            isdir = self.sftp.isdir
            exists = self.sftp.exists
            listdir = self.sftp.listdir
            inject_packets_from_pcap = self._inject_packets_from_remote_pcap
        
        pcap_dir = self._path_join(output_dir, 'out', 'pcap')

        # if there is a per-process capture, use it as it contains the richest context
        if isdir(self._path_join(pcap_dir, 'processes')):
            for container in listdir(self._path_join(pcap_dir, 'processes')):
                for pcap in listdir(self._path_join(pcap_dir, 'processes', container)):
                    pid = pcap.split('_')[-2]
                    comm = '_'.join(pcap.split('_')[:-2]) # don't naively take the first part because process name may contain underscores
                    yield f'PID {pid} ({comm})'
                    inject_packets_from_pcap(self._path_join(pcap_dir, 'processes', container, pcap))
        
        # the next preferred capture type is per-command
        elif isdir(self._path_join(pcap_dir, 'commands')):
            for container in listdir(self._path_join(pcap_dir, 'commands')):
                for pcap in listdir(self._path_join(pcap_dir, 'commands', container)):
                    yield f'command {pcap.removesuffix(".pcap")}'
                    inject_packets_from_pcap(self._path_join(pcap_dir, 'commands', container, pcap))
        
        # the next preferred capture type is per-container
        elif isdir(self._path_join(pcap_dir, 'containers')):
            for pcap in listdir(self._path_join(pcap_dir, 'containers')):
                yield f'container {pcap.removesuffix(".pcap")}'
                inject_packets_from_pcap(self._path_join(pcap_dir, 'containers', pcap))
        
        # the least preferred capture type is the single pcap, which doesn't contain any context
        elif exists(self._path_join(pcap_dir, 'single.pcap')):
            yield f'single PCAP'
            inject_packets_from_pcap(self._path_join(pcap_dir, 'single.pcap'))
    
    def _path_join(self, *parts) -> str:
        global local

        if local:
            return os.path.join(*parts)
        else:
            return '/'.join([*parts])
    
    def _inject_packets_from_local_pcap(self, pcap_file: str):
        self._inject_packets_from_pcap(pcap_file, pcap_file)
    
    def _inject_packets_from_remote_pcap(self, pcap_file: str):
        tmp_pcap = os.path.join(TMP_DIR, 'tmp.pcap')
        self.sftp.get(pcap_file, tmp_pcap)
        self._inject_packets_from_pcap(tmp_pcap, pcap_file)
        os.remove(tmp_pcap)
    
    def _inject_packets_from_pcap(self, pcap_file: str, pcap_full_path: str):
        with open(pcap_file, 'rb') as f:
            scanner = pcapng.FileScanner(f)

            for block in scanner:
                # don't write section header blocks, as sections cannot be interleaved
                if isinstance(block, pcapng.blocks.SectionHeader):
                    continue
                
                block.section = self.data_output_manager.get_current_section()

                if isinstance(block, pcapng.blocks.InterfaceDescription):
                    # we did not encounter this file yet
                    if pcap_full_path not in self.file_state:
                        block.interface_id = PacketInjector.CURRENT_IFACE_ID
                        PacketInjector.CURRENT_IFACE_ID += 1
                        self.data_output_manager.register_interface(block)
                        self.file_state[pcap_full_path] = (block.interface_id, 0)
                    else:
                        continue
                
                elif isinstance(block, pcapng.blocks.EnhancedPacket):
                    # don't write packets that we already encountered
                    if block.timestamp <= self.file_state[pcap_full_path][1]:
                        continue

                    block.interface_id = self.file_state[pcap_full_path][0]
                    self.file_state[pcap_full_path] = (block.interface_id, block.timestamp)
                
                self.data_output_manager.write_block(block)


class ControlOutputManager:
    def __init__(self, control_outf: BinaryIO):
        self._control_outf = control_outf
        self._lock = Lock()
    
    def disable_button(self, button: int):
        self._control_write(button, CTRL_CMD_DISABLE, b'')
    
    def enable_button(self, button: int):
        self._control_write(button, CTRL_CMD_ENABLE, b'')
    
    def set_button_text(self, button: int, text: str):
        self._control_write(button, CTRL_CMD_SET, text.encode())

    def _control_write(self, arg: int, cmd: int, payload: bytes):
        msg = bytearray()

        length = len(payload) + 2
        high8 = (length >> 16) & 0xff
        low16 = length & 0xffff

        msg += struct.pack('>sBHBB', b'T', high8, low16, arg, cmd)
        msg += payload

        with self._lock:
            self._control_outf.write(msg)
            self._control_outf.flush()


def control_read(inf: BinaryIO) -> Tuple[int, int, bytes]:
    header = inf.read(6)
    magic, high8, low16, arg, cmd = struct.unpack('>sBHBB', header)

    if magic != b'T':
        raise ValueError(f'unexpected control magic value {magic}')
    
    length = (high8 << 16) + low16
    payload = inf.read(length - 2) if length > 2 else None

    return arg, cmd, payload


def toolbar_control(control_inf: BinaryIO, control_output_manager: ControlOutputManager, output_dir: str, sftp: SFTPManager, packet_injector: PacketInjector):
    global running, copy_output, inject_packets, local

    toolbar_copy_output = True
    toolbar_inject_packets = True

    while True:
        try:
            arg, _, payload = control_read(control_inf)
        except OSError:
            break
        if not running:
            break

        if arg == CTRL_ARG_STOP:
            control_output_manager.disable_button(CTRL_ARG_STOP)
            control_output_manager.set_button_text(CTRL_ARG_STOP, 'Stopping...')
            copy_output = toolbar_copy_output
            inject_packets = toolbar_inject_packets
            stop_capture(is_error=False)
        
        elif arg == CTRL_ARG_COPY_ON_STOP:
            toolbar_copy_output = payload == b'\x01'
        
        elif arg == CTRL_ARG_INJECT_PACKETS_ON_STOP:
            toolbar_inject_packets = payload == b'\x01'
        
        elif arg == CTRL_ARG_COPY_OUTPUT and not local:
            control_output_manager.disable_button(CTRL_ARG_COPY_OUTPUT)
            control_output_manager.set_button_text(CTRL_ARG_COPY_OUTPUT, 'Copying output folder...')
            for path in sftp.copy_dir_from_remote(REMOTE_CAPTURE_OUTPUT_DIR, output_dir):
                control_output_manager.set_button_text(CTRL_ARG_COPY_OUTPUT, f'Copying {path.removeprefix(f"{REMOTE_CAPTURE_OUTPUT_DIR}/")}')
            control_output_manager.set_button_text(CTRL_ARG_COPY_OUTPUT, 'Copy output')
            control_output_manager.enable_button(CTRL_ARG_COPY_OUTPUT)
        
        elif arg == CTRL_ARG_INJECT_PACKETS:
            control_output_manager.disable_button(CTRL_ARG_INJECT_PACKETS)
            
            for pcap_desc in packet_injector.inject_packets():
                control_output_manager.set_button_text(CTRL_ARG_INJECT_PACKETS, f'Injecting packets from {pcap_desc}')
            
            control_output_manager.set_button_text(CTRL_ARG_INJECT_PACKETS, 'Inject packets')
            control_output_manager.enable_button(CTRL_ARG_INJECT_PACKETS)


def toolbar_thread(control_inf: BinaryIO, control_output_manager: ControlOutputManager, output_dir: str, sftp: SFTPManager, packet_injector: PacketInjector):
    try:
        toolbar_control(control_inf, control_output_manager, output_dir, sftp, packet_injector)
    except Exception:
        stop_capture(is_error=True)
        raise


def periodic_packet_injector(control_output_manager: ControlOutputManager, packet_injector: PacketInjector, interval: int):
    global args, running

    # no periodic injection
    if interval == 0:
        return
    
    # check if we are capturing packets
    if args.capture_artifacts is None:
        return
    if not any(['network' in artifact for artifact in args.capture_artifacts.split(',')]):
        return
    
    sleep(interval)

    while running:
        control_output_manager.disable_button(CTRL_ARG_INJECT_PACKETS)

        for pcap_desc in packet_injector.inject_packets():
                control_output_manager.set_button_text(CTRL_ARG_INJECT_PACKETS, f'Injecting packets from {pcap_desc}')
        
        control_output_manager.set_button_text(CTRL_ARG_INJECT_PACKETS, 'Inject packets')
        control_output_manager.enable_button(CTRL_ARG_INJECT_PACKETS)

        sleep(interval)


def packet_injector_thread(control_output_manager: ControlOutputManager, packet_injector: PacketInjector, interval: int):
    try:
        periodic_packet_injector(control_output_manager, packet_injector, interval)
    except Exception:
        stop_capture(is_error=True)
        raise


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
        raise ValueError('no SSH client provided')
    
    return send_ssh_command(ssh_client, command)


def error(msg: str) -> NoReturn:
    sys.stderr.write(f'{msg}\n')
    stop_capture(is_error=True)
    raise RuntimeError()


def exit_cb(_signum, _frame):
    stop_capture(is_error=False)


def build_docker_run_command(args: argparse.Namespace, local: bool, sshd_pid: Optional[int] = None) -> str:
    tracee_options = get_effective_tracee_options(args)

    command = 'docker run -d'

    # when not using docker for Windows or Mac, we connect Tracee to the local network
    if not local or (local and LINUX):
        command += f' --network=host'
        data_addr = '127.0.0.1'
    # when using docker for Windows or Mac, we connect back to the built-in host dns
    else:
        data_addr = 'host.docker.internal'

    if len(args.container_name) > 0:
        command += f' --name {args.container_name}'
    
    logfile = args.logfile if local else REMOTE_CAPTURE_LOGFILE
    output_dir = args.output_dir if local else REMOTE_CAPTURE_OUTPUT_DIR
    new_entrypoint = os.path.join(os.path.dirname(__file__), 'tracee-capture', 'new-entrypoint.sh') if local else REMOTE_CAPTURE_NEW_ENTRYPOINT
    command += f' {args.docker_options} -v {logfile}:/logs.log:rw -v {output_dir}:/output:rw -v {new_entrypoint}:/new-entrypoint.sh --entrypoint /new-entrypoint.sh {args.container_image} {tracee_options}'

    # add exclusions that may spam the capture
    if sshd_pid is not None:
        command += f' --scope pid!={sshd_pid}'
    
    if 'comm=' not in tracee_options: # make sure there is no comm filter in place, otherwise it will be overriden
        command += f' --scope comm!=tracee'

        # these exclusions are needed only when Wireshark is running on the same host that is being recorded
        if local and LINUX:
            command += f' --scope comm!="{READER_COMM}" --scope comm!=wireshark --scope comm!=dumpcap'
    
    command += f' --output forward:tcp://{data_addr}:{DATA_PORT} --log file:/logs.log --capture dir:/output --capture clear-dir --capabilities add=cap_dac_override'

    return command


def handle_connection(transport: paramiko.Transport, dst_addr: str, dst_port: int):
    global running

    # wait for incoming connection
    channel = transport.accept(None)

    # connect to the tunnel's receiving end
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((dst_addr, dst_port))
    except ConnectionRefusedError:
        sys.stderr.write(f'could not connect to {(dst_addr, dst_port)}\n')
        return
    
    while running:
        r, _, _ = select([sock, channel], [], [])
        if sock in r:
            data = sock.recv(TRACEE_OUTPUT_BUF_CAPACITY)
            if len(data) == 0:
                continue
            channel.send(data)
        if channel in r:
            data = channel.recv(TRACEE_OUTPUT_BUF_CAPACITY)
            if len(data) == 0:
                continue
            sock.send(data)
    
    channel.close()
    sock.close()


def prepare_local_capture(args: argparse.Namespace):
    # create empty file to get logs from Tracee
    if os.path.isdir(args.logfile):
        os.rmdir(args.logfile)
    open(args.logfile, 'w').close()

    # create directory for Tracee output files
    if os.path.isdir(args.output_dir):
        shutil.rmtree(args.output_dir)
    elif os.path.isfile(args.output_dir):
        os.remove(args.output_dir)
    os.makedirs(args.output_dir)
    os.chmod(args.output_dir, 0o2775) # g+ws


def prepare_remote_capture(args: argparse.Namespace, ssh_client: paramiko.SSHClient, sftp: SFTPManager) -> int:
    # remove preexisting Tracee logs file
    if os.path.isdir(args.logfile):
        shutil.rmtree(args.logfile)
    elif os.path.isfile(args.logfile):
        os.remove(args.logfile)
    
    # remove preexisting Tracee output directory
    if os.path.isdir(args.output_dir):
        shutil.rmtree(args.output_dir)
    elif os.path.isfile(args.output_dir):
        os.remove(args.output_dir)
    
    # prepare ssh tunnel to receive output
    ssh_data_client = ssh_connect(args)

    # on Windows, the previous capture doesn't terminate before the current one when restarting the capture,
    # so we have to wait a bit to give the previous capture a chance to clean up its forwarded ports
    for i in range(10):
        try:
            ssh_data_client.get_transport().request_port_forward('127.0.0.1', DATA_PORT)
        except paramiko.SSHException as ex:
            # not Windows - this failure is not because of a previous capture that is in the process of stopping
            if not WINDOWS:
                error(str(ex))
            
            if 'TCP forwarding request denied' in str(ex):
                # this was the last attempt
                if i == 9:
                    error(str(ex))
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

    # create empty Tracee logs file to be mounted into the Tracee container
    # (this is necessary because if it doesn't exist, docker will assume it needs to be a directory)
    _, err, returncode = send_ssh_command(ssh_client, f'rm -rf {REMOTE_CAPTURE_LOGFILE} && touch {REMOTE_CAPTURE_LOGFILE}')
    if returncode != 0:
        error(f'error creating file for Tracee logs, stderr dump:\n{err}')
    
    # create directory for Tracee output files
    _, err, returncode = send_ssh_command(ssh_client, f'rm -rf {REMOTE_CAPTURE_OUTPUT_DIR} && mkdir {REMOTE_CAPTURE_OUTPUT_DIR} && chmod g+ws {REMOTE_CAPTURE_OUTPUT_DIR}')
    if returncode != 0:
        error(f'error creating output directory for Tracee, stderr dump:\n{err}')
    
    # copy new container entrypoint
    sftp.put(os.path.join(os.path.dirname(__file__), 'tracee-capture', 'new-entrypoint.sh'), REMOTE_CAPTURE_NEW_ENTRYPOINT)
    _, err, returncode = send_ssh_command(ssh_client, f"chmod +x {REMOTE_CAPTURE_NEW_ENTRYPOINT}")
    if returncode != 0:
        error(f'error changing permissions on new entrypoint script, stderr dump:\n{err}')
    
    # get pid of sshd responsible for the ssh tunnel (it constantly polls its sockets which may spam the capture)
    out, err, returncode = send_ssh_command(ssh_data_client, "echo $PPID")
    if returncode != 0:
        error(f'error getting sshd pid, stderr dump:\n{err}')
    
    return int(out)


def tracee_capture(args: argparse.Namespace):
    global local, running, container_id, copy_output, inject_packets, control_output_manager

    # Open the toolbar control pipes before anything that can fail runs.
    # This is done because Wireshark hangs if the extcap dies before the control pipes were opened.
    control_outf = open(args.extcap_control_out, 'wb')
    control_inf = open(args.extcap_control_in, 'rb')

    # Initialize the output before anything that can fail runs. This is done because Wireshark enters
    # a corrupt state if the extcap dies before a pcap/pcapng header was written to the output pipe.
    data_output_manager = DataOutputManager(args.fifo)

    # sleep to let Wireshark's initial message to arrive, otherwise Wireshark displays an error if we immediately exit and don't receive the message
    sleep(0.1)

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
    
    if not local and not args.remote_host:
        error('no remote host specified')
    
    # catch termination signals from Wireshark (currently on Windows it is not possible to be notified of
    # termination, as a workaround we monitor Wireshark's pipe breaking in the reader thread as a sign of termination)
    signal.signal(signal.SIGINT, exit_cb)
    signal.signal(signal.SIGTERM, exit_cb)

    if local:
        ssh_client = None
        sftp = None
        sshd_pid = None
        prepare_local_capture(args)
    else:
        ssh_client = ssh_connect(args)
        sftp = SFTPManager(ssh_client.open_sftp())
        sshd_pid = prepare_remote_capture(args, ssh_client, sftp)
    
    # remove container from previous run
    if len(args.container_name) > 0:
        _, err, returncode = send_command(local, f"docker rm -f {args.container_name}", ssh_client)
        if returncode != 0 and 'No such container' not in err:
            error(f'docker rm -f returned with error code {returncode}, stderr dump:\n{err}')
    
    # initialize control output manager and packet injector
    control_output_manager = ControlOutputManager(control_outf)
    packet_injector = PacketInjector(data_output_manager, sftp, args.output_dir)
    
    # start toolbar control thread
    control_th = Thread(target=toolbar_control, args=(control_inf, control_output_manager, args.output_dir, sftp, packet_injector), daemon=True)
    control_th.start()

    # start reader thread
    reader_th = Thread(target=reader_thread, args=(data_output_manager,))
    reader_th.start()

    # start packet injector thread
    packet_injector_th = Thread(target=packet_injector_thread, args=(control_output_manager, packet_injector, args.packet_injection_interval), daemon=True)
    packet_injector_th.start()

    # run Tracee container
    command = build_docker_run_command(args, local, sshd_pid=sshd_pid)
    out, err, returncode = send_command(local, command, ssh_client)
    if returncode != 0:
        error(f'docker run returned with error code {returncode}, stderr dump:\n{err}')
    container_id = out.rstrip('\n')

    # wait until Tracee exits (triggered by stop_capture or by an error)
    command = f'docker wait {container_id}'
    _, err, returncode = send_command(local, command, ssh_client)
    if returncode != 0:
        error(f'docker wait returned with error code {returncode}, stderr dump:\n{err}')
    
    running = False

    # inject captured packets
    if inject_packets:
        for i, pcap_desc in enumerate(packet_injector.inject_packets(queue=True)):
            # Disable the button only after injection started.
            # If we were to disable it before this loop, if an injection was already in progress
            # it would have reenabled the button after we disabled it.
            if i == 0:
                control_output_manager.disable_button(CTRL_ARG_INJECT_PACKETS)
            control_output_manager.set_button_text(CTRL_ARG_INJECT_PACKETS, f'Injecting packets from {pcap_desc}')
        control_output_manager.set_button_text(CTRL_ARG_INJECT_PACKETS, 'Inject packets')

    # copy Tracee logs file and output directory
    if not local:
        sftp.get(REMOTE_CAPTURE_LOGFILE, args.logfile)
        sftp.remove(REMOTE_CAPTURE_LOGFILE)
        sftp.remove(REMOTE_CAPTURE_NEW_ENTRYPOINT)

        if copy_output:
            control_output_manager.disable_button(CTRL_ARG_COPY_OUTPUT)
            control_output_manager.set_button_text(CTRL_ARG_COPY_OUTPUT, 'Copying output folder...')
            for path in sftp.copy_dir_from_remote(REMOTE_CAPTURE_OUTPUT_DIR, args.output_dir):
                control_output_manager.set_button_text(CTRL_ARG_COPY_OUTPUT, f'Copying {path.removeprefix(f"{REMOTE_CAPTURE_OUTPUT_DIR}/")}')
            _, err, returncode = send_ssh_command(ssh_client, f"rm -rf {REMOTE_CAPTURE_OUTPUT_DIR}")
            if returncode != 0:
                error(f'error removing output directory from remote machine, stderr dump:\n{err}')
    
    # the capture has been stopped because of an error condition,
    # so the stop_capture function already removed the container
    if container_id is None:
        return
    
    # check Tracee logs for errors
    logs_err = ''
    command = f'docker logs {container_id}'
    _, err, returncode = send_command(local, command, ssh_client)
    if returncode != 0:
        if 'dead or marked for removal' not in err:
            error(f'docker logs returned with error code {returncode}, stderr dump:\n{err}')
    else:
        logs_err = err
    
    # remove Tracee container
    command = f'docker rm {container_id}'
    _, err, returncode = send_command(local, command, ssh_client)
    if returncode != 0 and 'No such container' not in err and 'is already in progress' not in err:
        error(f'docker rm returned with error code {returncode}, stderr dump:\n{err}')
    
    if len(logs_err) > 0:
        error(f'Tracee exited with error message:\n{logs_err}')


def main():
    global args

    parser = argparse.ArgumentParser(prog=os.path.basename(__file__), description='Capture events and packets using Tracee')

    # extcap arguments
    parser.add_argument('--extcap-interfaces', help='Provide a list of interfaces to capture from', action='store_true')
    parser.add_argument('--extcap-version', help='Shows the version of this utility', nargs='?', default='')
    parser.add_argument('--extcap-config', help='Provide a list of configurations for the given interface', action='store_true')
    parser.add_argument('--extcap-interface', help='Provide the interface to capture from')
    parser.add_argument('--extcap-dlts', help='Provide a list of dlts for the given interface', action='store_true')
    parser.add_argument('--capture', help='Start the capture routine', action='store_true')
    parser.add_argument('--fifo', help='Use together with capture to provide the fifo to dump data to')
    parser.add_argument('--extcap-reload-option', help='Reload elements for the given option')
    parser.add_argument('--extcap-control-in', help='Used to get control messages from toolbar')
    parser.add_argument('--extcap-control-out', help='Used to send control messages to toolbar')

    # custom arguments
    parser.add_argument('--capture-type', type=str, default=DEFAULT_CAPTURE_TYPE)
    parser.add_argument('--logfile', type=str, default=DEFAULT_LOGFILE)
    parser.add_argument('--output-dir', type=str, default=DEFAULT_OUTPUT_DIR)
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
    parser.add_argument('--capture-artifacts', type=str)
    parser.add_argument('--network-filtered', action='store_true', default=False)
    parser.add_argument('--network-snaplen', type=str, default=DEFAULT_SNAPLEN)
    parser.add_argument('--packet-injection-interval', type=int, default=DEFAULT_PACKET_INJECTION_INTERVAL)
    parser.add_argument('--preset', type=str)
    parser.add_argument('--preset-file', type=str)

    args = parser.parse_args()

    if args.extcap_version and not args.extcap_interfaces:
        show_version()
        sys.exit(0)

    if args.extcap_interfaces or args.extcap_interface is None:
        show_interfaces()
        sys.exit(0)
    
    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit('An interface must be provided or the selection must be displayed')
    
    if args.extcap_config:
        show_config(args.extcap_reload_option)
    elif args.extcap_dlts:
        show_dlts()
    elif args.capture:
        tracee_capture(args)
    
    sys.exit(0)


if __name__ == '__main__':
    #sys.stderr = open(os.path.join(TMP_DIR, 'capture_stderr.log'), 'w')
    #sys.stderr.write(f'{sys.argv}\n')
    #sys.stderr.flush()
    
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
    finally:
        sys.stderr.flush()
