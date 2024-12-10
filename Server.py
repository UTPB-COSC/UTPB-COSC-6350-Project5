import socket
import threading
from BluetoothDevice import BluetoothDevice

class BluetoothServer:
    def __init__(self, host='localhost', port=12345):
        self.device = BluetoothDevice(is_server=True)
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen(1)

    def handle_client(self, client_socket):
        try:
            client_socket.send(self.device.serialize_public_key(self.device.public_key))
            client_public_key_bytes = client_socket.recv(4096)
            self.device.peer_public_key = self.device.deserialize_public_key(client_public_key_bytes)
            client_socket.send(self.device.serialize_public_key(self.device.ecdh_public_key))
            client_ecdh_public_key_bytes = client_socket.recv(4096)
            shared_key = self.device.generate_shared_key(client_ecdh_public_key_bytes)
            for i in range(3):
                decrypted_msg = self.device.receive_message(client_socket)
                print(f"Server received: {decrypted_msg.decode()}")
                response = f"Server response {i}"
                self.device.send_message(client_socket, response)
        finally:
            client_socket.close()

    def start(self):
        print(f"Server listening on {self.host}:{self.port}")
        while True:
            client_socket, addr = self.socket.accept()
            print(f"Connection from {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()