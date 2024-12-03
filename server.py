import socket
import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from colorama import Fore, Style

def print_colored(message, color):
    print(color + message + Style.RESET_ALL)

def print_debug(message):
    # Write detailed information to a log file
    with open("debug.log", "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

class BluetoothZigbeeServer:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port

        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # Diffie-Hellman parameters for key exchange
        self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.private_dh_key = self.parameters.generate_private_key()

        self.shared_secret = None
        self.session_key = None

    def perform_key_exchange(self, conn):
        print_colored(f"[{datetime.now()}] [SERVER] Performing key exchange...", Fore.CYAN)

        # Send RSA public key
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(public_key_bytes)
        print_debug("Sent RSA public key to client.")

        # Receive client's RSA public key
        client_public_key_bytes = conn.recv(4096)
        print_debug("Received RSA public key from client.")

        # Send Diffie-Hellman parameters
        parameter_bytes = self.parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        conn.sendall(parameter_bytes)
        print_debug("Sent DH parameters to client.")

        # Send DH public key
        server_dh_public_key_bytes = self.private_dh_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(server_dh_public_key_bytes)
        print_debug("Sent DH public key to client.")

        # Receive client's DH public key
        client_dh_public_key_bytes = conn.recv(4096)
        client_dh_public_key = serialization.load_pem_public_key(client_dh_public_key_bytes)
        print_debug("Received DH public key from client.")

        # Compute shared secret and derive session key
        self.shared_secret = self.private_dh_key.exchange(client_dh_public_key)
        self.session_key = hashlib.sha256(self.shared_secret).digest()
        print_colored(f"[{datetime.now()}] [SERVER] ***** Key exchange completed *****", Fore.GREEN)

    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the message to make its length a multiple of 16
        padded_message = message + b' ' * (16 - len(message) % 16)
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

        return iv + encrypted_message


def main():
    server = BluetoothZigbeeServer()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((server.host, server.port))
        s.listen()
        print_colored(f"[{datetime.now()}] [SERVER] Listening on {server.host}:{server.port}...", Fore.GREEN)

        conn, addr = s.accept()
        with conn:
            print_colored(f"[{datetime.now()}] [SERVER] Connected by {addr}", Fore.CYAN)

            # Perform key exchange
            server.perform_key_exchange(conn)

            # Send encrypted messages
            messages = [
                b"This is Kishor",
                b"This is project 5",
                b"Encrypted packet"
            ]
            for msg in messages:
                encrypted_msg = server.encrypt_message(msg)
                conn.sendall(encrypted_msg)
                print_colored(f"[SERVER] Sent encrypted message: {msg}", Fore.MAGENTA)


if __name__ == "__main__":
    main()