import socket
import random
import hashlib
from Crypto.Cipher import AES

# Diffie-Hellman parameters
p = 23  # Prime number
g = 5   # Primitive root

# Server setup
def start_server():
    print("==== SERVER INITIALIZATION ====")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(1)
    print("SERVER: Awaiting client connection on port 12345...")

    client_socket, client_address = server.accept()
    print(f"SERVER: Connected to client at {client_address}")

    # Key Exchange Phase
    print("\n--- KEY EXCHANGE PROCESS ---")
    a = random.randint(1, p - 1)
    A = pow(g, a, p)
    print(f"SERVER: Private key generated.")
    print(f"SERVER: Calculated public value (A): {A}")

    # Send server's public value to client
    client_socket.send(str(A).encode())
    print("SERVER: Public value (A) sent to client.")

    # Receive client's public value
    B = int(client_socket.recv(1024).decode())
    print(f"SERVER: Received client's public value (B): {B}")

    # Calculate shared secret key
    shared_secret = pow(B, a, p)
    session_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]
    print("SERVER: Shared session key has been computed.")

    # Encrypted Message Handling Phase
    print("\n--- MESSAGE HANDLING ---")
    encrypted_message = client_socket.recv(1024)
    if encrypted_message:
        cipher = AES.new(session_key, AES.MODE_ECB)
        decrypted_message = cipher.decrypt(encrypted_message).strip()
        # Directly show the decrypted message with a custom text.
        print(f"SERVER: Received and decoded message from client: {decrypted_message.decode()}")
    else:
        print("SERVER: No message received from client.")

    client_socket.close()
    server.close()
    print("\n==== SERVER SHUTDOWN COMPLETE ====")

if __name__ == "__main__":
    start_server()
