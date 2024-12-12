# Imported packages
import threading
import socket
import hashlib
import time
from Crypto import *

# Handles a connected client
def handle_client(conn, addr):
    try:
        print(f"[SERVER] Connection established with {addr}")
        p, g = 23, 5  # Diffie-Hellman parameters
        ecdhe = ECDHE(p, g)

        # Step 1: Send Server's public key
        conn.sendall(str(ecdhe.public_key).encode())

        # Step 2: Receive Client's public key
        client_public_key = int(conn.recv(1024).decode())

        # Step 3: Compute the shared secret
        shared_secret = ecdhe.compute_shared_secret(client_public_key)
        session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()
        print(f"[SERVER] Session key: {session_key}")

        # Step 4: Define a shared device address
        device_address = int.from_bytes(b'\xe7\x53\x41\xb0\x81\xf5', byteorder='big')  # Shared address
        print(f"[SERVER] Device address: {device_address.to_bytes(6, byteorder='big').hex()}")

        frame_counter = 0
        used_counters = set()

        # Step 5: Encrypt and send messages
        messages = ["Hello, client!", "This is the server speaking.", "Do you see this, client?"]
        for message in messages:
            nonce, ciphertext = aes_ccm_encrypt(session_key, message, frame_counter, device_address)
            conn.sendall(nonce + ciphertext)
            frame_counter += 1
            time.sleep(1)

        # Step 6: Receive and decrypt client messages
        buffer = b""
        while True:
            data = conn.recv(1024)
            if not data:
                break

            buffer += data
            while len(buffer) >= 16:  # Ensure at least 12-byte nonce + 4-byte ciphertext
                nonce = buffer[:12]
                buffer = buffer[12:]

                # Determine ciphertext length dynamically or based on fixed application rules
                ciphertext_end = buffer.find(b'\xe7\x53\x41\xb0\x81\xf5')  # Look for next nonce or end of buffer
                if ciphertext_end == -1:
                    ciphertext_end = len(buffer)

                ciphertext = buffer[:ciphertext_end]
                buffer = buffer[ciphertext_end:]

                print(f"[SERVER] Ciphertext: {ciphertext.hex()}")

                # Validate and process nonce
                counter = int.from_bytes(nonce[6:], byteorder='big')
                if counter in used_counters:
                    print("[SERVER] Replay detected!")
                    continue
                used_counters.add(counter)

                # Decrypt message
                try:
                    decrypted_message = aes_ccm_decrypt(session_key, nonce, ciphertext)
                    print(f"[SERVER] Decrypted message: {decrypted_message}")
                except Exception as e:
                    print(f"[SERVER] Failed to decrypt message: {e}")
                    break

    except Exception as e:
        import traceback
        print(f"[SERVER] Error: {e}")
        traceback.print_exc()
    finally:
        conn.close()

# Starts the server to listen for incoming client connections
def start_server(host='127.0.0.1', port=5001):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"[SERVER] Listening on {host}:{port}")
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

# Catches the main thread
if __name__ == "__main__":
    start_server()
