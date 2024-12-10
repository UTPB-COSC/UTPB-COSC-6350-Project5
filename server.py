
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

HOST = '0.0.0.0'
PORT = 9999

# Logging Utility
def log(msg, level="SERVER"):
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

# Server Implementation
def handle_client(conn):
    try:
        log_section("Key Exchange")
        private, public = generate_keys()
        conn.send(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

        client_pub_key_bytes = conn.recv(2048)
        client_pub_key = serialization.load_pem_public_key(client_pub_key_bytes)

        shared = derive_secret(private, client_pub_key)
        session_key = get_session_key(shared)
        log("Session key established")

        while True:
            len_data = conn.recv(4)
            if not len_data:
                log("Client disconnected")
                break

            msg_len = int.from_bytes(len_data, 'big')
            data = conn.recv(msg_len)
            check_hmac(session_key, data[32:], data[:32])
            msg = decrypt(data[32:], session_key)
            log(f"Client sent a message: {msg}")

            response = f"Received: {msg}"
            enc_resp = encrypt(response, session_key)
            hmac_resp = create_hmac(session_key, enc_resp)
            conn.send(len(hmac_resp + enc_resp).to_bytes(4, 'big'))
            conn.send(hmac_resp + enc_resp)
            log("Response sent")

    except Exception as e:
        log(f"Error: {e}", "ERROR")
    finally:
        conn.close()

def start_server():
    log_section("Server Start")
    log("Server is running")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen(5)
        log(f"Listening on {HOST}:{PORT}")

        while True:
            conn, addr = server.accept()
            log(f"Connected to {addr}")
            handle_client(conn)

if __name__ == "__main__":
    start_server()
