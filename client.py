
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from datetime import datetime
import os

HOST = '127.0.0.1'
PORT = 9999

# Logging Utility
def log(msg, level="CLIENT"):
    print(f"[{level}] {datetime.now()} - {msg}")

def log_section(title):
    print("\n" + "*" * 60)
    print(f"{title:^60}")
    print("*" * 60)

# Cryptographic Utilities
def generate_keys():
    private = ec.generate_private_key(ec.SECP256R1())
    return private, private.public_key()

def derive_secret(priv_key, pub_key):
    return priv_key.exchange(ec.ECDH(), pub_key)

def get_session_key(secret, salt=b"Handshake", info=b"Session"):
    return HKDF(hashes.SHA256(), 32, salt, info).derive(secret)

def encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data.encode()) + padder.finalize()
    return iv + cipher.encryptor().update(padded) + cipher.encryptor().finalize()

def decrypt(data, key):
    iv, encrypted = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = cipher.decryptor().update(encrypted) + cipher.decryptor().finalize()
    return (unpadder.update(decrypted) + unpadder.finalize()).decode()

def create_hmac(key, msg):
    h = HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()

def check_hmac(key, msg, hmac_value):
    h = HMAC(key, hashes.SHA256())
    h.update(msg)
    h.verify(hmac_value)

# Client Implementation
def run_client():
    log_section("Client Start")
    log("Client is running")

    try:
        log_section("Key Exchange")
        log("Generating keys")
        private, public = generate_keys()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            log(f"Connecting to {HOST}:{PORT}")
            sock.connect((HOST, PORT))
            log("Connected")

            server_pub_key_bytes = sock.recv(2048)
            server_pub_key = serialization.load_pem_public_key(server_pub_key_bytes)

            sock.send(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            shared = derive_secret(private, server_pub_key)
            session_key = get_session_key(shared)
            log("Session key derived")

            while True:
                msg = input("Send Message (type 'exit' to quit): ")
                if msg.lower() == "exit":
                    log("Closing session")
                    break

                enc_msg = encrypt(msg, session_key)
                hmac_value = create_hmac(session_key, enc_msg)
                sock.send(len(hmac_value + enc_msg).to_bytes(4, 'big'))
                sock.send(hmac_value + enc_msg)

                resp_len = int.from_bytes(sock.recv(4), 'big')
                resp_data = sock.recv(resp_len)
                check_hmac(session_key, resp_data[32:], resp_data[:32])
                response = decrypt(resp_data[32:], session_key)
                log(f"Server says: {response}")

    except Exception as e:
        log(f"Error: {e}", "ERROR")

if __name__ == "__main__":
    run_client()
