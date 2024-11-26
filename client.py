import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

HOST = 'localhost'
PORT = 12345
RSA_KEY_SIZE = 2048

client_rsa_key = RSA.generate(RSA_KEY_SIZE)

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        s.send(client_rsa_key.publickey().export_key())

        server_public_key = RSA.import_key(s.recv(1024))
        encrypted_aes_key = s.recv(1024)

        cipher_rsa = PKCS1_OAEP.new(client_rsa_key)
        aes_session_key = cipher_rsa.decrypt(encrypted_aes_key)

        for _ in range(3):
            message = b"Hello Server!"
            
            cipher_aes = AES.new(aes_session_key, AES.MODE_CBC)
            encrypted_message = cipher_aes.iv + cipher_aes.encrypt(pad(message, AES.block_size))
            s.send(encrypted_message)

            encrypted_response = s.recv(1024)
            cipher_aes = AES.new(aes_session_key, AES.MODE_CBC, iv=encrypted_response[:AES.block_size])
            decrypted_response = unpad(cipher_aes.decrypt(encrypted_response[AES.block_size:]), AES.block_size)
            
            print(f"Received from server: {decrypted_response.decode()}")

if __name__ == "__main__":
    start_client()