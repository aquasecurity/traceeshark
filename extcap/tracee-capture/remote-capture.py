#!/usr/bin/env python3

from typing import NoReturn, Tuple

from ctypes import cdll, byref, create_string_buffer
import fcntl
import json
import os
import select
import socket
import struct
import subprocess as subp
import sys
from threading import Thread


TRACEE_OUTPUT_PIPE = '/tmp/tracee_output.pipe'
TRACEE_OUTPUT_PIPE_CAPACITY = 262144 # enough to hold the largest event encountered so far
TRACEE_LOGS_FILE = '/tmp/tracee_logs.log'
F_SETPIPE_SZ = 1031 # python < 3.10 does not have fcntl.F_SETPIPE_SZ
READER_COMM = 'tracee-capture'

running = True
reader_th = None


def send_command(command: str) -> Tuple[bytes, bytes, int]:
    proc = subp.Popen(['/bin/sh', '-c', command], stdout=subp.PIPE, stderr=subp.PIPE)
    out, err = proc.communicate()
    return out, err, proc.returncode


def cleanup():
    try:
        os.remove(TRACEE_OUTPUT_PIPE)
    except FileNotFoundError:
        pass
    try:
        os.remove(sys.argv[1])
    except FileNotFoundError:
        pass


def error(msg: str) -> NoReturn:
    global running
    running = False
    
    cleanup()

    sys.stderr.write(f'{msg}\n')
    sys.exit(1)


def stop_capture():
    global running, container_id

    running = False

    if container_id is not None:
        command = f'docker kill {container_id}'
        _, err, returncode = send_command(command)
        if returncode != 0:
            error(f'docker kill returned with error code {returncode}, stderr dump:\n{err}')


def control_worker(ctrl_port: int):
    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # local machine should already be listening on an established SSH tunnel, try connecting once
    ctrl_sock.settimeout(1)
    try:
        ctrl_sock.connect(('127.0.0.1', ctrl_port))
    except socket.timeout:
        sys.stderr.write(f"couldn't connect to control channel")
        stop_capture()
        return

    ctrl_sock.settimeout(0.1)

    msg = None
    while running:
        try:
            msg = ctrl_sock.recv(1024)
        except socket.timeout:
            continue
        else:
            break
    
    if msg is not None and msg != b'stop':
        raise ValueError()

    ctrl_sock.close()
    
    stop_capture()


def set_proc_name(newname: str):
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(newname)+1)
    buff.value = newname.encode()
    libc.prctl(15, byref(buff), 0, 0, 0)


def send_msg(conn: socket.socket, msg: bytes):
    # prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    conn.sendall(msg)


def read_output(data_port: int):
    global running

    # change our process name so we can exclude it (otherwise it may flood capture with pipe read activity)
    # TODO: using a PID is more robust, but currently there is no way to filter by PID in namespace (required when running on WSL)
    set_proc_name(READER_COMM)

    # connect to local machine on the prepared SSH tunnel
    tracee_output_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # local machine should already be listening on an established SSH tunnel, try connecting once
    tracee_output_sock.settimeout(1)
    try:
        tracee_output_sock.connect(('127.0.0.1', data_port))
    except socket.timeout:
        sys.stderr.write(f"couldn't connect to data channel")
        stop_capture()
        return

    tracee_output_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, TRACEE_OUTPUT_PIPE_CAPACITY)

    # open tracee output pipe
    tracee_output_pipe_f = os.open(TRACEE_OUTPUT_PIPE, os.O_RDONLY | os.O_NONBLOCK)
    fcntl.fcntl(tracee_output_pipe_f, F_SETPIPE_SZ, TRACEE_OUTPUT_PIPE_CAPACITY)

    while running:
        r, _, _ = select.select([ tracee_output_pipe_f ], [], [], 0.1)
        if tracee_output_pipe_f in r:
            data = os.read(tracee_output_pipe_f, TRACEE_OUTPUT_PIPE_CAPACITY)
        else:
            continue

        try:
            send_msg(tracee_output_sock, data)
        # local machine closed the connection
        except BrokenPipeError:
            running = False
    
    os.close(tracee_output_pipe_f)
    tracee_output_sock.close()


def main():
    global running
    
    with open(sys.argv[1], 'r') as f:
        config = json.loads(f.read())

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
    if os.path.isdir(TRACEE_LOGS_FILE):
        os.rmdir(TRACEE_LOGS_FILE)
    open(TRACEE_LOGS_FILE, 'w').close()

    # create reader thread
    reader_th = Thread(target=read_output, args=(config['data_port'],))
    reader_th.start()
    
    command = f'docker run -d'
    
    if config['container_name'] is not None:
        command += f" --name {config['container_name']}"
    
    command += f" {config['docker_options']} -v {TRACEE_OUTPUT_PIPE}:/output.pipe:rw -v {TRACEE_LOGS_FILE}:/logs.log:rw {config['container_image']} {config['tracee_options']}"

    # add exclusion for reader that may spam the capture
    # TODO: add exclusion to sshd which handles data port forwarding
    if 'comm=' not in config['tracee_options']: # make sure there is no comm filter in place, otherwise it will be overriden
        command += f' --scope comm!="{READER_COMM}" --scope comm!=tracee'
    
    command += f' -o json:/output.pipe --log file:/logs.log'

    out, err, returncode = send_command(command)
    if returncode != 0:
        error(f'docker run returned with error code {returncode}, stderr dump:\n{err}')
    
    global container_id
    container_id = out.decode().rstrip('\n')

    # create control thread
    control_th = Thread(target=control_worker, args=(config['ctrl_port'],))
    control_th.start()

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
    
    control_th.join()

    cleanup()


if __name__ == '__main__':
    #sys.stderr = open('/tmp/capture_stderr.log', 'w')
    main()
