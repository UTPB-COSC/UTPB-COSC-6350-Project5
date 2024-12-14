import socket
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Diffie-Hellman parameters
p = 23  # Prime number
g = 5   # Primitive root

# Client setup
def start_client():
    print("==== CLIENT INITIALIZATION ====")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 12345))
    print("CLIENT: Connected to server at localhost:12345")

    # Key Exchange Phase
    print("\n--- KEY EXCHANGE PROCESS ---")
    b = random.randint(1, p - 1)
    B = pow(g, b, p)
    print(f"CLIENT: Private key generated.")
    print(f"CLIENT: Calculated public value (B): {B}")

    # Receive server's public value
    A = int(client.recv(1024).decode())
    print(f"CLIENT: Received server's public value (A): {A}")

    # Send client's public value to server
    client.send(str(B).encode())
    print("CLIENT: Public value (B) sent to server.")

    # Calculate shared secret key
    shared_secret = pow(A, b, p)
    session_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]
    print("CLIENT: Shared session key has been computed.")

    # Command Execution Phase
    print("\n--- COMMAND EXECUTION ---")
    message = "Hi there, this is project 5"
    padded_message = pad(message.encode(), 16)  # Pads message to be a multiple of 16 bytes
    cipher = AES.new(session_key, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(padded_message)
    print("CLIENT: Encrypting message to server...")
    client.send(encrypted_message)
    print("CLIENT: Encrypted message sent to server.")

    print(f"CLIENT: Custom message displayed instead of the original decrypted message: {message}")
    client.close()
    print("\n==== CLIENT SHUTDOWN COMPLETE ====")

if __name__ == "__main__":
    start_client()
