import socket
import hashlib
from my_crypto import aes_ccm_encrypt, aes_ccm_decrypt, derive_session_key
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, ECDH
from cryptography.hazmat.primitives import serialization
import os

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555

def start_client(server_host=SERVER_HOST, server_port=SERVER_PORT):
    try:
        client_private_key = generate_private_key(SECP256R1())
        client_public_key = client_private_key.public_key()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            print(f"[CLIENT] Connecting to server at {server_host}:{server_port}...")
            client_socket.connect((server_host, server_port))

            # Step 1: Exchange public keys
            server_public_bytes = client_socket.recv(1024)
            server_public_key = serialization.load_der_public_key(server_public_bytes)

            client_public_bytes = client_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.sendall(client_public_bytes)

            # Step 2: Compute shared secret and derive session key
            shared_secret = client_private_key.exchange(ECDH(), server_public_key)
            session_key = derive_session_key(shared_secret)
            #print(f"[CLIENT] Session key derived: {session_key.hex()}")

            # Step 3: Define shared device address
            device_address = int.from_bytes(b'\xe7\x53\x41\xb0\x81\xf5', byteorder='big')
            #print(f"[CLIENT] Device address: {device_address.to_bytes(6, byteorder='big').hex()}")

            print("[CLIENT] Preparing to send messages to the server...")
            # Step 5: Encrypt and send messages to the server
            messages = [
                "Hello, there!.",
                "This is for Project 5",
                "I'm guessing this work great."
            ]

            # Initialize frame counter
            frame_counter = 0

            for message in messages:
                nonce = os.urandom(8) + frame_counter.to_bytes(3, byteorder='big')  # Unique nonce
                nonce, ciphertext, tag = aes_ccm_encrypt(message, session_key)
                packet = nonce + ciphertext + tag
                #print(f"[CLIENT] Sending packet: Nonce={nonce.hex()}, Ciphertext={ciphertext.hex()}, Tag={tag.hex()}")

                # Add length prefix
                length_prefix = len(packet).to_bytes(4, byteorder='big')
                print(
                    f"[CLIENT] Sending packet of length {len(packet)}: Nonce={nonce.hex()}, Ciphertext={ciphertext.hex()}, Tag={tag.hex()}")

                client_socket.sendall(length_prefix + packet)
                print(f"[CLIENT] Sent encrypted message: {ciphertext.hex()}")
                frame_counter += 1

    except Exception as e:
        print(f"[CLIENT] Error: {e}")
        import traceback
        traceback.print_exc()

# Entry point for the client
if __name__ == "__main__":
    start_client()
