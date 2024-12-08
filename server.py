
import socket
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.dh import (
    DHParameterNumbers, DHPrivateNumbers
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7

# Server-side parameters
DH_PRIME = 23  # Example prime for Diffie-Hellman
DH_BASE = 5    # Example base for Diffie-Hellman

# Helper functions
def generate_dh_keypair():
    private_key = random.randint(1, DH_PRIME - 1)
    public_key = pow(DH_BASE, private_key, DH_PRIME)
    return private_key, public_key

def derive_session_key(private_key, public_key):
    return pow(public_key, private_key, DH_PRIME)

def aes_encrypt(key, plaintext):
    iv = random.randbytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return unpadder.update(plaintext) + unpadder.finalize()

# Server implementation
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 65432))
server_socket.listen(1)

print("Server waiting for connection...")
conn, addr = server_socket.accept()
print(f"Connection established with {addr}")

# Diffie-Hellman key exchange
private_key, public_key = generate_dh_keypair()
conn.sendall(str(public_key).encode())
client_public_key = int(conn.recv(1024).decode())

session_key = derive_session_key(private_key, client_public_key).to_bytes(16, 'big')

# Send and receive encrypted messages
while True:
    encrypted_message = conn.recv(1024)
    if not encrypted_message:
        break
    message = aes_decrypt(session_key, encrypted_message)
    print(f"Received (decrypted): {message.decode()}")

    response = f"Server received: {message.decode()}"
    encrypted_response = aes_encrypt(session_key, response.encode())
    conn.sendall(encrypted_response)

conn.close()
server_socket.close()
