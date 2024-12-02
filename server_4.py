import socket
from cryptography.hazmat.primitives import serialization
from my_crypto_4 import (generate_ecdh_key_pair, derive_shared_secret, derive_session_key,
    aes_encrypt, aes_decrypt, generate_hmac, verify_hmac)
import os
from datetime import datetime

HOST = '0.0.0.0'
PORT = 5555

def log(message, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{level}] [{timestamp}] {message}")

def log_separator(phase_name):
    print("\n" + "=" * 50)
    print(f"{phase_name:^50}") 
    print("=" * 50)

def handle_client(conn):
    try:
        log_separator("Key Exchange Phase")
        log("Generating server's ECDHE key pair...")
        server_private_key, server_public_key = generate_ecdh_key_pair()

        # Send the server's public key
        conn.sendall(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # Receive the client's public key
        client_public_bytes = conn.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_bytes)

        # Derive the shared session key
        shared_secret = derive_shared_secret(server_private_key, client_public_key)
        session_key = derive_session_key(shared_secret, salt=b"BluetoothZigbee", info=b"802.15 Handshake")
        log(f"Session key derived successfully: {session_key.hex()}")

        # Pairing phase
        log_separator("Pairing Phase")
        pairing_code = os.urandom(4)
        conn.send(pairing_code)
        log(f"Generated pairing code: {pairing_code.hex()}")
        ack = conn.recv(1024)
        if ack != b"PAIRING_ACK":
            log("Pairing failed. Disconnecting client.", level="ERROR")
            return
        log("Pairing successful.")

        # Secure command exchange
        log_separator("Command Handling Phase")
        while True:
            # Receive command length
            length_data = conn.recv(4)
            if not length_data:  # Client has disconnected
                log("Client disconnected gracefully.", level="INFO")
                break

            length = int.from_bytes(length_data, byteorder="big")
            if length == 0:  # No command received
                log("Empty command received. Closing connection.", level="INFO")
                break

            # Receive command
            encrypted_data = conn.recv(length)
            command_hmac = encrypted_data[:32]
            encrypted_command = encrypted_data[32:]

            try:
                verify_hmac(session_key, encrypted_command, command_hmac)
                command = aes_decrypt(encrypted_command, session_key).decode()
                log(f"Received command: {command}")

                if command.lower() == "exit":
                    log("Client requested to exit. Closing connection.", level="INFO")
                    break

                # Respond to the command
                response = f"{command} acknowledged by server."
                encrypted_response = aes_encrypt(response.encode(), session_key)
                response_hmac = generate_hmac(session_key, encrypted_response)
                conn.sendall(len(response_hmac + encrypted_response).to_bytes(4, byteorder="big"))
                conn.sendall(response_hmac + encrypted_response)
                log(f"Sent response: {response}")

            except ValueError as ve:
                log(f"Error processing command: {ve}", level="ERROR")
                break

    except Exception as e:
        log(f"An error occurred: {e}", level="ERROR")
    finally:
        log_separator("Connection Closed")
        conn.close()

def start_server():
    # Start server
    log_separator("===== Bluetooth/Zigbee Secure Server =====")
    log("Starting the server...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        log(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = server_socket.accept()
            log(f"New connection from {addr}")
            handle_client(conn)

if __name__ == "__main__":
    start_server()