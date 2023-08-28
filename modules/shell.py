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
        self.send_is_running = True
        self.receive_is_running = True
        self.old_settings = termios.tcgetattr(sys.stdin.fileno())
        self.send_thread = None
        self.receive_thread = None
        self.queue = Queue()
        self.socket.client_socket.settimeout(1)

        columns, lines = shutil.get_terminal_size()

        self.socket.client_socket.send(f"export COLUMNS={columns}; export LINES={lines}\n".encode())
        if not pty:
            self.socket.client_socket.send(b"script /dev/null\n")
            self.socket.client_socket.send(b"alias exit='echo PotatoeMunchkinExit132@@'\n")
            # self.socket.client_socket.send(b"clear\n")
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
                            self.exit()
        finally:
            termios.tcsetattr(0, termios.TCSADRAIN, self.old_settings)

    def receive_data(self):
        test = False
        while self.receive_is_running:
            try:
                ready_to_read, _, _ = select.select([self.socket.client_socket], [], [], 1)
                if ready_to_read:
                    data = self.socket.client_socket.recv(1024)
                    if b"PotatoeMunchkinExit132@@" in data:
                        self.exit(close=False)
                        return
                    if not data:
                        raise ConnectionError
                    os.write(1, data)
                else:
                    continue
            except (ConnectionError, OSError) as e:
                self.receive_is_running = False
                break
            except Exception as e:
                break

    def run(self):
        self.receive_thread = threading.Thread(target=self.receive_data)
        self.send_thread = threading.Thread(target=self.send_data)

        signal.signal(signal.SIGINT, self.send_interrupt)
        signal.signal(signal.SIGTSTP, self.send_suspend)
        signal.signal(signal.SIGUSR1, handle_signal)

        self.receive_thread.start()
        self.send_thread.start()

        self.receive_thread.join()
        self.send_thread.join()

    def exit(self, close=True):
        self.send_is_running = False
        self.receive_is_running = False
        termios.tcsetattr(0, termios.TCSADRAIN, self.old_settings)
        if close:
            self.socket.client_socket.close()
            self.socket.server_socket.close()
            return
        else:
            return