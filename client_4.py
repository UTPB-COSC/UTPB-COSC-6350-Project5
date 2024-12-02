import socket
from my_crypto_4 import (generate_ecdh_key_pair, derive_shared_secret, derive_session_key,
    aes_encrypt, aes_decrypt, generate_hmac, verify_hmac)
from cryptography.hazmat.primitives import serialization
from datetime import datetime

HOST = '127.0.0.1'
PORT = 5555

def log(message, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{level}] [{timestamp}] {message}")

def log_separator(phase_name):
    print("\n" + "=" * 50)
    print(f"{phase_name:^50}") #center
    print("=" * 50)

def get_user_device():
    print("Select device type:")
    print("1. Light")
    print("2. Thermostat")
    print("3. Security Alarm")
    print("4. Exit")
    device_choice = input("Enter the number corresponding to the device: ")

    if device_choice == "4":
        return "Exit"
    elif device_choice == "1":
        return "Light"
    elif device_choice == "2":
        return "Thermostat"
    elif device_choice == "3":
        return "Security Alarm"
    else:
        print("Invalid selection. Defaulting to Light.")
        return "Light"
    
def tcp_client():
    #Run the Bluetooth/Zigbee client.
    log_separator("===== Bluetooth/Zigbee Secure Client =====")

    try:
        # Generate client's ECDHE key pair
        log_separator("Key Exchange Phase")
        log("Generating client's ECDHE key pair...")
        client_private_key, client_public_key = generate_ecdh_key_pair()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            log(f"Connecting to server at {HOST}:{PORT}...")
            client_socket.connect((HOST, PORT))
            log("Connected to server.")

            # Key exchange
            log("Receiving server's public key...")
            server_public_bytes = client_socket.recv(2048)
            server_public_key = serialization.load_pem_public_key(server_public_bytes)
            client_socket.send(client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            shared_secret = derive_shared_secret(client_private_key, server_public_key)
            session_key = derive_session_key(shared_secret, salt=b"BluetoothZigbee", info=b"802.15 Handshake")
            log(f"Session key derived successfully: {session_key.hex()}")

            # Pairing phase
            log_separator("Pairing Phase")
            pairing_code = client_socket.recv(1024)
            client_socket.send(b"PAIRING_ACK")
            log(f"Pairing completed with code: {pairing_code.hex()}")

            while True:
                log_separator("Command Selection Phase")
                device = get_user_device()
                if device == "Exit":
                    log("Exiting client.")
                    break

                print(f"Available commands for {device}:")
                commands = {
                    "Light": ["Turn on light", "Turn off light"],
                    "Thermostat": ["Set temperature to 70°F", "Set temperature to 75°F"],
                    "Security Alarm": ["Activate alarm", "Deactivate alarm"]
                }.get(device, [])
                for i, command in enumerate(commands, start=1):
                    print(f"{i}. {command}")

                command_index = int(input("Select a command: ")) - 1
                selected_command = commands[command_index]

                log_separator("Command Execution Phase")
                
                # Encrypt and send the command
                encrypted_command = aes_encrypt(selected_command.encode(), session_key)
                command_hmac = generate_hmac(session_key, encrypted_command)
                client_socket.sendall(len(command_hmac + encrypted_command).to_bytes(4, byteorder="big"))
                client_socket.sendall(command_hmac + encrypted_command)
                log(f"Sent command: {selected_command}")

                # Receive and verify the server's response
                response_length = int.from_bytes(client_socket.recv(4), byteorder="big")
                encrypted_response = client_socket.recv(response_length)
                response_hmac = encrypted_response[:32]
                response_message = encrypted_response[32:]

                verify_hmac(session_key, response_message, response_hmac)
                response = aes_decrypt(response_message, session_key).decode()
                log(f"Received response: {response}")

    except Exception as e:
        log(f"An error occurred: {e}", level="ERROR")

if __name__ == "__main__":
    tcp_client()