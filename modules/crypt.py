from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import json
import os

class ServerPyEncryption():
    def __init__(self, gen=2, key_size=2048):
        self.parameters = dh.generate_parameters(generator=gen, key_size=key_size)
        self.p = self.parameters.parameter_numbers().p
        self.g = self.parameters.parameter_numbers().g

    def get_derived_key(self, client):
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
        shared_key = server_pk.exchange(client_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
    
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


class ClientPyEncryption():
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
