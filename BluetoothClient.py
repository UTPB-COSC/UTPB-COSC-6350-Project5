import socket
import json
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class BluetoothClient:
    def _init_(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.client_random = os.urandom(16)
        self.session_key = None
        self.link_key = None
        self.device_name = "TestClient"
        self.device_class = "0x200404"

    def generate_link_key(self, server_random):
        key_info = b"bluetooth-link-key"
        hkdf = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=key_info)
        material = server_random + self.client_random
        return hkdf.derive(material)
    
    def derive_session_key(self, shared_secret):
        key_info = b"bluetooth-session-key"
        hkdf = HKDF(algorithm=hashes.SHA256(),length=32,salt=self.link_key,info=key_info)
        return hkdf.derive(shared_secret)
    
    def encrypt_data(self, data):
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return {'iv': base64.b64encode(iv).decode(),'data': base64.b64encode(encrypted).decode()}
    
    def decrypt_data(self, encrypted_dict):
        iv = base64.b64decode(encrypted_dict['iv'])
        encrypted = base64.b64decode(encrypted_dict['data'])
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode()
    
    def connect(self, pin_code="123456"):
        print(f"Connecting to device at {self.host}:{self.port}")
        try:
            self.socket.connect((self.host, self.port))
            discovery_msg = json.loads(self.socket.recv(4096).decode())
            print(f"Found device: {discovery_msg['name']} ({discovery_msg['class']})")
            link_msg = {'type': 'LINK_INFO','random': base64.b64encode(self.client_random).decode()}
            self.socket.send(json.dumps(link_msg).encode())
            server_info = json.loads(self.socket.recv(4096).decode())
            server_random = base64.b64decode(server_info['random'])
            self.link_key = self.generate_link_key(server_random)
            auth_msg = {'type': 'AUTH','pin': pin_code}
            self.socket.send(json.dumps(auth_msg).encode())
            key_msg = json.loads(self.socket.recv(4096).decode())
            server_public_key = serialization.load_der_public_key(base64.b64decode(key_msg['public_key']))
            public_bytes = self.private_key.public_key().public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            response_key_msg = {'type': 'KEY_EXCHANGE','public_key': base64.b64encode(public_bytes).decode()}
            self.socket.send(json.dumps(response_key_msg).encode())
            shared_secret = self.private_key.exchange(ec.ECDH(), server_public_key)
            self.session_key = self.derive_session_key(shared_secret)
            print("Pairing completed successfully!")
            while True:
                message = input("Enter message (or 'quit' to exit): ")
                self.socket.send(json.dumps(self.encrypt_data(message)).encode())
                encrypted_response = json.loads(self.socket.recv(4096).decode())
                response = self.decrypt_data(encrypted_response)
                print(f"Server response: {response}")
                if message.lower() == "quit": break
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            self.socket.close()
            
if _name_ == "_main_":
    client = BluetoothClient()
    client.connect()