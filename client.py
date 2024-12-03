import socket
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from colorama import Fore, Style

def print_colored(message, color):
    print(color + message + Style.RESET_ALL)


class BluetoothZigbeeClient:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port

        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        self.shared_secret = None
        self.session_key = None

    def perform_key_exchange(self, s):
        print_colored(f"[{datetime.now()}] [CLIENT] Performing key exchange...", Fore.CYAN)

        # Receive RSA public key
        server_public_key_bytes = s.recv(4096)
        print(f"[CLIENT] Received RSA public key from server.")

        # Send RSA public key
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        s.sendall(public_key_bytes)
        print(f"[CLIENT] Sent RSA public key to server.")

        # Receive Diffie-Hellman parameters
        parameter_bytes = s.recv(4096)
        parameters = serialization.load_pem_parameters(parameter_bytes)

        # Receive server's DH public key
        server_dh_public_key_bytes = s.recv(4096)
        server_dh_public_key = serialization.load_pem_public_key(server_dh_public_key_bytes)

        # Generate DH key pair and send public key
        client_private_dh_key = parameters.generate_private_key()
        client_dh_public_key_bytes = client_private_dh_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        s.sendall(client_dh_public_key_bytes)
        print(f"[CLIENT] Sent DH public key to server.")

        # Compute shared secret and derive session key
        self.shared_secret = client_private_dh_key.exchange(server_dh_public_key)
        self.session_key = hashlib.sha256(self.shared_secret).digest()
        print_colored(f"[{datetime.now()}] [CLIENT] Key exchange completed.", Fore.GREEN)

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]

        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_message.rstrip()


def main():
    client = BluetoothZigbeeClient()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((client.host, client.port))
        print_colored(f"[{datetime.now()}] [CLIENT] Connected to server.", Fore.CYAN)

        # Perform key exchange
        client.perform_key_exchange(s)

        # Receive and decrypt messages
        while True:
            encrypted_msg = s.recv(4096)
            if not encrypted_msg:
                break

            decrypted_msg = client.decrypt_message(encrypted_msg)
            print_colored(f"[CLIENT] Received decrypted message: {decrypted_msg}", Fore.MAGENTA)


if __name__ == "__main__":
    main()