import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

HOST = 'localhost'
PORT = 12345
AES_KEY_SIZE = 16  
RSA_KEY_SIZE = 2048

server_rsa_key = RSA.generate(RSA_KEY_SIZE)

def handle_client(client_socket):
    client_public_key = RSA.import_key(client_socket.recv(1024))
    client_socket.send(server_rsa_key.publickey().export_key())

    aes_session_key = get_random_bytes(AES_KEY_SIZE)
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_session_key)
    client_socket.send(encrypted_aes_key)

    while True:
        try:
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                break

            cipher_aes = AES.new(aes_session_key, AES.MODE_CBC, iv=encrypted_data[:AES.block_size])
            decrypted_data = unpad(cipher_aes.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
            
            print(f"Received from client: {decrypted_data.decode()}")

            response = b"ACK: " + decrypted_data
            cipher_aes = AES.new(aes_session_key, AES.MODE_CBC)
            encrypted_response = cipher_aes.iv + cipher_aes.encrypt(pad(response, AES.block_size))
            client_socket.send(encrypted_response)

        except Exception as e:
            print(f"Error: {e}")
            break

    client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()