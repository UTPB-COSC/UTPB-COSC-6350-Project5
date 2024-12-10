import os
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding as sym_padding

class SecurityParams:
    def __init__(self):
        self.aes_key = None
        self.sequence_number = 0

class BluetoothDevice:
    def __init__(self, is_server=True):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ecdh_public_key = self.ecdh_private_key.public_key()
        self.security_params = SecurityParams()
        self.is_server = is_server
        self.peer_public_key = None
        
    def serialize_public_key(self, key):
        return key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    def deserialize_public_key(self, key_bytes):
        return serialization.load_pem_public_key(key_bytes)

    def generate_shared_key(self, peer_public_key_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        shared_key = self.ecdh_private_key.exchange(ec.ECDH(), peer_public_key)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data')
        self.security_params.aes_key = hkdf.derive(shared_key)
        return self.security_params.aes_key

    def encrypt_message(self, message):
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.security_params.aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_message(self, message):
        iv = message[:16]
        ciphertext = message[16:]
        cipher = Cipher(algorithms.AES(self.security_params.aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def send_message(self, sock, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        encrypted_msg = self.encrypt_message(message)
        msg_len = len(encrypted_msg)
        sock.sendall(struct.pack('!I', msg_len))
        sock.sendall(encrypted_msg)

    def receive_message(self, sock):
        msg_len_bytes = sock.recv(4)
        if not msg_len_bytes:
            return None
        msg_len = struct.unpack('!I', msg_len)[0]
        chunks = []
        bytes_received = 0
        while bytes_received < msg_len:
            chunk = sock.recv(min(msg_len - bytes_received, 4096))
            if not chunk:
                raise ConnectionError("Connection broken")
            chunks.append(chunk)
            bytes_received += len(chunk)
        encrypted_msg = b''.join(chunks)
        return self.decrypt_message(encrypted_msg)