import socket
from cryptography.hazmat.primitives import serialization
from BluetoothDevice import BluetoothDevice

class BluetoothClient:
    def __init__(self, host='localhost', port=12345):
        self.device = BluetoothDevice(is_server=False)
        self.host = host
        self.port = port

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            server_public_key_bytes = self.socket.recv(4096)
            self.device.peer_public_key = self.device.deserialize_public_key(server_public_key_bytes)
            self.socket.send(self.device.serialize_public_key(self.device.public_key))
            server_ecdh_public_key_bytes = self.socket.recv(4096)
            self.socket.send(self.device.serialize_public_key(self.device.ecdh_public_key))
            shared_key = self.device.generate_shared_key(server_ecdh_public_key_bytes)
            for i in range(3):
                message = f"Client message {i}"
                self.device.send_message(self.socket, message)
                decrypted_response = self.device.receive_message(self.socket)
                print(f"Client received: {decrypted_response.decode()}")
        finally:
            self.socket.close()