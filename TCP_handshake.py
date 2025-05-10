# Gabriel Kyle Manalastas
# 8000232781
# manalastas_g32781@utpb.edu
# Better late than never, better something than nothing.

# TCP handshake Project 5

import socket
import hashlib
import threading
import time
import random  
from cryptography.hazmat.primitives.ciphers.aead import AESCCM  

class ECDHE:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = random.randint(2, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def computeSharedSecret(self, other_public_key):
        return pow(other_public_key, self.private_key, self.p)


def aesCcmEncrypt(session_key, plaintext, frame_counter, device_address):
    key = bytes.fromhex(session_key)  
    nonce = device_address.to_bytes(6, byteorder='big') + frame_counter.to_bytes(6, byteorder='big')
    aesccm = AESCCM(key, tag_length=4)  
    ciphertext = aesccm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext


def aesccmDecrypt(session_key, nonce, ciphertext):
    key = bytes.fromhex(session_key)  
    aesccm = AESCCM(key, tag_length=4)  
    plaintext = aesccm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def startClient(server_host='127.0.0.1', server_port=5001):
    try:
        p, g = 23, 5
        ecdhe = ECDHE(p, g)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((server_host, server_port))

            ap_public_key = int(client_socket.recv(1024).decode())
            client_socket.sendall(str(ecdhe.public_key).encode())

            shared_secret = ecdhe.computeSharedSecret(ap_public_key)
            session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()
            print(f"[CLIENT] Session key: {session_key}")

            device_address = int.from_bytes(b'\xe7\x53\x41\xb0\x81\xf5', byteorder='big')  # Shared address
            print(f"[CLIENT] Device address: {device_address.to_bytes(6, byteorder='big').hex()}")

            frame_counter = 0

            for _ in range(3):
                data = client_socket.recv(1024)
                nonce, ciphertext = data[:12], data[12:]
                print(f"[CLIENT] Ciphertext: {ciphertext.hex()}")
                decrypted_message = aesccmDecrypt(session_key, nonce, ciphertext)
                print(f"[CLIENT] Deciphered message: {decrypted_message}")

            messages = ["Greetings Server", "This is the client.", "Confrim receipt, server"]
            for message in messages:
                nonce, ciphertext = aesCcmEncrypt(session_key, message, frame_counter, device_address)
                client_socket.sendall(nonce + ciphertext)  
                frame_counter += 1
    except Exception as e:
        import traceback
        print(f"[CLIENT] Error: {e}")
        traceback.print_exc()


# Protocol for when Client connects to server
def handleClient(conn, addr):
    try:
        print(f"[SERVER] Connection established with {addr}")
        p, g = 23, 5  # Diffie-Hellman parameters
        ecdhe = ECDHE(p, g)

        # Server public key
        conn.sendall(str(ecdhe.public_key).encode())

        # Client public key
        client_public_key = int(conn.recv(1024).decode())

        shared_secret = ecdhe.computeSharedSecret(client_public_key)
        session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()
        print(f"[SERVER] Session key: {session_key}")

        device_address = int.from_bytes(b'\xe7\x53\x41\xb0\x81\xf5', byteorder='big')  # Shared address
        print(f"[SERVER] Device address: {device_address.to_bytes(6, byteorder='big').hex()}")

        frame_counter = 0
        used_counters = set()

        # Encrypt and send messages
        messages = ["Greetings Client", "This is the server.", "Confirm Receipt, client?"]
        for message in messages:
            nonce, ciphertext = aesCcmEncrypt(session_key, message, frame_counter, device_address)
            conn.sendall(nonce + ciphertext)
            frame_counter += 1
            time.sleep(1)

        # Receive and decrypt client messages
        buffer = b""
        while True:
            data = conn.recv(1024)
            if not data:
                break

            buffer += data
            while len(buffer) >= 16: 
                nonce = buffer[:12]
                buffer = buffer[12:]

                ciphertext_end = buffer.find(b'\xe7\x53\x41\xb0\x81\xf5')  
                if ciphertext_end == -1:
                    ciphertext_end = len(buffer)

                ciphertext = buffer[:ciphertext_end]
                buffer = buffer[ciphertext_end:]

                print(f"[SERVER] Ciphertext: {ciphertext.hex()}")

                counter = int.from_bytes(nonce[6:], byteorder='big') #insurance against replay attacks
                if counter in used_counters:
                    print("[SERVER] Replay detected!")
                    continue
                used_counters.add(counter)

                try:
                    decrypted_message = aesccmDecrypt(session_key, nonce, ciphertext)
                    print(f"[SERVER] Deciphered message: {decrypted_message}")
                except Exception as e:
                    print(f"[SERVER] Failed to decipher message: {e}")
                    break

    except Exception as e:
        import traceback
        print(f"[SERVER] Error: {e}")
        traceback.print_exc()
    finally:
        print ("Main program complete.") 
        conn.close()

def start_server(host='127.0.0.1', port=5001):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"[SERVER] Listening on {host}:{port}")
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handleClient, args=(conn, addr)).start()

# Catches the main thread
if __name__ == "__main__":
    server_thread = threading.Thread(target=start_server)
    server_thread.start()
    
    startClient()

    server_thread.join()
