import socket
import threading
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, ECDH
from cryptography.hazmat.primitives import serialization
from my_crypto import aes_ccm_decrypt, derive_session_key
import time

# Server configuration
HOST = '127.0.0.1'
PORT = 5555

# Handles a connected client
def handle_client(conn, addr):
    try:
        print(f"[SERVER] Connection established with {addr}")

        # Step 1: Generate ECC Key Pair
        server_private_key = generate_private_key(SECP256R1())
        server_public_key = server_private_key.public_key()

        # Step 2: Send Server Public Key
        server_public_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(server_public_bytes)

        # Step 3: Receive Client Public Key
        client_public_bytes = conn.recv(1024)
        client_public_key = serialization.load_der_public_key(client_public_bytes)

        # Step 4: Derive Shared Secret and Session Key
        shared_secret = server_private_key.exchange(ECDH(), client_public_key)
        session_key = derive_session_key(shared_secret)
        print(f"[SERVER] Session key derived: {session_key.hex()}")

        # Step 5: Define Device Address (Bluetooth/Zigbee compliance)
        device_address = int.from_bytes(b'\xe7\x53\x41\xb0\x81\xf5', byteorder='big')
        print(f"[SERVER] Device address: {device_address.to_bytes(6, byteorder='big').hex()}")

        frame_counter = 0
        used_counters = set()

        # Step 6: Receive and Decrypt Messages from the Client
        while True:
            print("[SERVER] Waiting to receive data...")

            # Read the length prefix (4 bytes)
            length_prefix = conn.recv(4)
            if not length_prefix:
                print("[SERVER] No more data from client. Closing connection.")
                break

            packet_length = int.from_bytes(length_prefix, byteorder='big')
            #print(f"[SERVER] Packet length: {packet_length}")

            # Read the full packet
            packet = b""
            while len(packet) < packet_length:
                chunk = conn.recv(packet_length - len(packet))
                if not chunk:
                    print("[SERVER] Connection closed unexpectedly.")
                    return
                packet += chunk

            #print(f"[SERVER] Received packet of length {len(packet)}: {packet.hex()}")

            if len(packet) < 11 + 16:  # Minimum length: 11-byte nonce + 16-byte tag
                print("[SERVER] Malformed packet received.")
                continue

            # Parse the packet
            nonce = packet[:11]
            ciphertext = packet[11:-16]
            tag = packet[-16:]

            # Decrypt the message
            try:
                decrypted_message = aes_ccm_decrypt(nonce, ciphertext, tag, session_key)
                print(f"[SERVER] Received (decrypted): {decrypted_message}")
            except ValueError as e:
                print(f"[SERVER] Decryption failed: {e}")

    except Exception as e:
        print(f"[SERVER] Error: {e}")
    finally:
        conn.close()
        print(f"[SERVER] Connection with {addr} closed.")

# Starts the server to listen for incoming connections
def start_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"[SERVER] Listening on {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

# Entry point for the server
if __name__ == "__main__":
    start_server()
