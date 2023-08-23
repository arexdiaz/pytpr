from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from modules.utils import NO_OUTPUT_SIGNAL
import logging
import select
import signal
import socket
import queue
import json
import time
import re
import os

logging.basicConfig(level=logging.INFO)

ORIGINAL_SIGTSTP = signal.getsignal(signal.SIGTSTP)
EXIT_CMD = " && echo _3X1T_5TATUS=$? || echo _3X1T_5TATUS=$?\n"

def pretty(s):
    try:
        s = re.sub(r"_3X1T_5TATUS=\w+", "", s.decode()).strip()
    except AttributeError:
        pass
    if s and s != NO_OUTPUT_SIGNAL:
        return s
    else:
        return None

def sig_handler(signum, frame):
    raise KeyboardBgInterrupt

def _sigtspt_check():
    try:
        msg = input("Put session in background? (y/n) > ")
    except (KeyboardInterrupt, KeyboardBgInterrupt):
        print("")
        _sigtspt_check()
    if msg.lower() == "y":
        return True
    elif msg.lower() == "n":
        return False
    else:
        _sigtspt_check()

def listen(host, port, py_state):
    if not py_state:
        sock = BashServerSocket()
    else:
        sock = PyServerSocket()

    try:
        sock.server_socket.bind((host, int(port)))
    except socket.error:
        logging.error("Address already in use")
        raise 
    
    logging.info(f"Started listener on {host, port}")

    try:
        sock.listen()
        if not sock.is_shell():
            logging.error("No shell found")
            return
    except KeyboardInterrupt:
        sock.server_socket.close()
        print("")
        return
    except BrokenPipeError:
        sock.server_socket.close()
        logging.error("BrokenPipeError")
        return

    return sock

def netshell_loop(shellObj):
    signal.signal(signal.SIGTSTP, sig_handler)

    if not shellObj.is_open:
        signal.signal(signal.SIGTSTP, ORIGINAL_SIGTSTP)
        return
    
    try:
        shellObj.cmdloop()
    except KeyboardInterrupt:
        print("")
        netshell_loop(shellObj)
    except KeyboardBgInterrupt:
        print("")
        msg =_sigtspt_check()
        if msg:
            signal.signal(signal.SIGTSTP, ORIGINAL_SIGTSTP)
            return
        else:
            netshell_loop(shellObj)
    except BrokenPipeError:
        signal.signal(signal.SIGTSTP, ORIGINAL_SIGTSTP)
        return

class KeyboardBgInterrupt(Exception):
    pass

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
        self.client_socket = None
        self.client_address = None


    def listen(self):

        self.server_socket.listen()

        readable, _, _ = select.select(self.inputs, self.outputs, self.inputs)

        for s in readable:
            if s is self.server_socket:
                self.client_socket, self.client_address = self.server_socket.accept()
                logging.info(f"Connection established with {self.client_address}")

                self.client_socket.setblocking(0)

                self.inputs.append(self.client_socket)
                self.message_queues[self.client_socket] = queue.Queue()
                

    def is_shell(self):
        self.client_socket.sendall(f"/bin/bash 2>&1\n".encode())
        self.client_socket.sendall(f"echo hello{EXIT_CMD}".encode())
        print("INFO:root:Validating if connection has shell.. ", end="")
        time.sleep(0.1)
        check = self.send_command("echo THIS_IS_A_TEST_STRING_IGNORE_PLS")
        print("ok!")
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

class Encryption():
    def __init__(self):
        GEN = 2
        KEY_SIZE = 2048
        self.parameters = dh.generate_parameters(generator=GEN, key_size=KEY_SIZE)
        self.p = self.parameters.parameter_numbers().p
        self.g = self.parameters.parameter_numbers().g

    def generate_shared_secret(self, client, p, g):
        server_pk = self.parameters.generate_private_key()

        # Prepare server public key to send to client
        server_pub_pem = server_pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        client.send(server_pub_pem)

        # Receive client's public key from the client
        client_public_key_pem = client.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)
        # Generate the shared secret
        return server_pk.exchange(client_public_key)
    
    def encrypt_message(self, message, derived_key):
        # Create an AES Cipher context with the derived key and a random IV
        iv = os.urandom(12)  # GCM uses a 12-byte IV
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the message and get the tag
        padder = padding.PKCS7(128).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        tag = encryptor.tag

        return iv + ciphertext + tag
    
    def decrypt_message(self, data, derived_key):
        iv = data[:12]  # GCM uses a 12-byte IV
        ciphertext = data[12:-16]  # assuming a 16-byte tag
        tag = data[-16:]

        # Create an AES Cipher context with the derived key and the received IV
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext and remove the padding
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_message) + unpadder.finalize()


class PyServerSocket():
    def __init__(self, sock_type=socket.SOCK_STREAM):
        self.server_socket = socket.socket(socket.AF_INET, sock_type)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client_socket = None
        self.client_address = None

        self.enc = Encryption()

    def listen(self):
        self.server_socket.listen(1)
        self.client_socket, self.client_address = self.server_socket.accept()
        logging.info(f"Connection established with {self.client_address}")

    def is_shell(self):
        self.client_socket.send(json.dumps({'p': self.enc.p, 'g': self.enc.g}).encode())
        logging.info("Validating if connection has shell..")
        check = pretty(self.send_command("echo hello"))
        if check == "hello":
            return True
        else:
            return False

    def send_command(self, command):
        chunk = b""
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(self.enc.generate_shared_secret(self.client_socket,
                                                 self.enc.p,self.enc.g))

        encrypted_message = self.enc.encrypt_message(command, derived_key)

        self.client_socket.sendall(encrypted_message)
        data_length_bytes = self.client_socket.recv(4)
        data_length = int.from_bytes(data_length_bytes, byteorder="big")
        data_bytes = bytearray()

        while len(data_bytes) < data_length:
            chunk = self.client_socket.recv(data_length - len(data_bytes))
            if chunk == b"":
                raise RuntimeError("socket connection broken")
            data_bytes.extend(chunk)

        return self.enc.decrypt_message(chunk, derived_key)

    def close(self):
        self.client_socket.close()
        self.server_socket.close()