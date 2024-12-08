
import socket
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7

# Client-side parameters
DH_PRIME = 23
DH_BASE = 5

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

# Client implementation
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 65432))

# Diffie-Hellman key exchange
private_key, public_key = generate_dh_keypair()
server_public_key = int(client_socket.recv(1024).decode())
client_socket.sendall(str(public_key).encode())

session_key = derive_session_key(private_key, server_public_key).to_bytes(16, 'big')

# Send and receive encrypted messages
for i in range(3):
    message = f"Hello Server, message {i+1}"
    encrypted_message = aes_encrypt(session_key, message.encode())
    client_socket.sendall(encrypted_message)

    encrypted_response = client_socket.recv(1024)
    response = aes_decrypt(session_key, encrypted_response)
    print(f"Received (decrypted): {response.decode()}")

client_socket.close()