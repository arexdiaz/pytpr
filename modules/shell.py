from concurrent.futures.thread import ThreadPoolExecutor
from queue import Queue
import signal
import select
import threading
import termios
import tty
import os
import sys
import shutil

def handle_signal(signum, frame):
    raise ConnectionError("Connection lost")

class RawShell:
    def __init__(self, sock, pty=False):
        self.socket = sock
        self.is_socket_open = True
        self.queue = Queue()
        self.send_thread = None
        self.receive_thread = None
        self.send_is_running = True
        self.receive_is_running = True
        self.socket.client_socket.settimeout(1)
        self.old_settings = termios.tcgetattr(sys.stdin.fileno())

        columns, lines = shutil.get_terminal_size()

        self.socket.client_socket.send(f"export TERM=xterm;export COLUMNS={columns}; export LINES={lines}\n".encode())

        if not pty:
            self.socket.client_socket.send(b"script /dev/null\n")
            self.socket.client_socket.send(b"alias exit='echo PotatoeMunchkinExit132@@'\n")
        self.socket.client_socket.send(b"alias _='echo wababbo@@'\n")
        while True:
            data = self.socket.client_socket.recv(1024)
            if b"alias _='echo wababbo@@'" in data:
                self.socket.client_socket.send(b"clear\n")
                break
                
            self.socket.client_socket.send(b" ")
        self.socket.client_socket.setblocking(1)
        data = self.socket.client_socket.recv(8192)

    def send_interrupt(self, signum, frame):
        self.socket.client_socket.send(b"\x03")

    def send_suspend(self, signum, frame):
        self.socket.client_socket.send(b"\x1A")

    def send_data(self):
        try:
            tty.setcbreak(0)
            while self.send_is_running:
                r, _, _ = select.select([0], [], [], 0.1)
                if r:
                    data = os.read(0, 1024)
                    if data:
                        try:
                            self.socket.client_socket.send(data)
                        except:
                            break
        finally:
            termios.tcsetattr(0, termios.TCSADRAIN, self.old_settings)

    def receive_data(self):
        test = False
        while self.receive_is_running:
            try:
                ready_to_read, _, _ = select.select([self.socket.client_socket], [], [], 1)
                if ready_to_read:
                    data = self.socket.client_socket.recv(1024)
                    if b"PotatoeMunchkinExit132@@" in data and not b"alias exit='echo PotatoeMunchkinExit132@@'" in data:
                        self.send_is_running = False
                        self.socket.client_socket.send(b"1")
                        break
                    if not data:
                        raise ConnectionError
                    os.write(1, data)
                else:
                    continue
            except (ConnectionError, OSError) as e:
                self.send_is_running = False
                break
            except Exception as e:
                break

    def run(self):
        with self.socket.lock:
            original_sigint = signal.getsignal(signal.SIGINT)
            original_sigstop = signal.getsignal(signal.SIGTSTP)

            signal.signal(signal.SIGINT, self.send_interrupt)
            signal.signal(signal.SIGTSTP, self.send_suspend)
            signal.signal(signal.SIGUSR1, handle_signal)

            with ThreadPoolExecutor(max_workers=2) as executor:
                executor.submit(self.receive_data)
                executor.submit(self.send_data)

            termios.tcsetattr(0, termios.TCSADRAIN, self.old_settings)
            
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTSTP, original_sigstop)

        return