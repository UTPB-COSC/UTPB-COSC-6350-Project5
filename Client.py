# Imported packages
import socket
import hashlib
from Crypto import *

# Connects to the server
def start_client(server_host='127.0.0.1', server_port=5001):
    try:
        p, g = 23, 5
        ecdhe = ECDHE(p, g)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((server_host, server_port))

            # Step 1: Receive server's public key and send client's public key
            ap_public_key = int(client_socket.recv(1024).decode())
            client_socket.sendall(str(ecdhe.public_key).encode())

            # Step 2: Compute the shared secret and derive the session key
            shared_secret = ecdhe.compute_shared_secret(ap_public_key)
            session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()
            print(f"[CLIENT] Session key: {session_key}")

            # Step 3: Define a shared device address
            device_address = int.from_bytes(b'\xe7\x53\x41\xb0\x81\xf5', byteorder='big')  # Shared address
            print(f"[CLIENT] Device address: {device_address.to_bytes(6, byteorder='big').hex()}")

            frame_counter = 0

            # Step 4: Receive and decrypt messages from the server
            for _ in range(3):
                data = client_socket.recv(1024)
                nonce, ciphertext = data[:12], data[12:]
                print(f"[CLIENT] Ciphertext: {ciphertext.hex()}")
                decrypted_message = aes_ccm_decrypt(session_key, nonce, ciphertext)
                print(f"[CLIENT] Decrypted message: {decrypted_message}")

            # Step 5: Encrypt and send messages back to the server
            messages = ["Hello, server!", "This is the client speaking.", "Do you see this, server?"]
            for message in messages:
                nonce, ciphertext = aes_ccm_encrypt(session_key, message, frame_counter, device_address)
                client_socket.sendall(nonce + ciphertext)  # Send one message at a time
                frame_counter += 1
    except Exception as e:
        import traceback
        print(f"[CLIENT] Error: {e}")
        traceback.print_exc()

# Catches the main thread
if __name__ == "__main__":
    start_client()
