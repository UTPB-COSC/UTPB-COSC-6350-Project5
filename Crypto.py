# Imported packages
import random  # For generating private keys in Diffie-Hellman
from cryptography.hazmat.primitives.ciphers.aead import AESCCM  # For AES-CCM encryption/decryption

# ECDHE Class for Diffie-Hellman Key Exchange
class ECDHE:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = random.randint(2, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, other_public_key):
        return pow(other_public_key, self.private_key, self.p)

# Encrypts a plaintext message using AES-CCM as defined by 802.15.4
def aes_ccm_encrypt(session_key, plaintext, frame_counter, device_address):
    key = bytes.fromhex(session_key)  # Convert session key from hex to bytes
    # Nonce construction: Source address (6 bytes) + Frame counter (6 bytes)
    nonce = device_address.to_bytes(6, byteorder='big') + frame_counter.to_bytes(6, byteorder='big')
    aesccm = AESCCM(key, tag_length=4)  # 4-byte authentication tag
    ciphertext = aesccm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

# Decrypts a ciphertext using AES-CCM as defined by 802.15.4
def aes_ccm_decrypt(session_key, nonce, ciphertext):
    key = bytes.fromhex(session_key)  # Convert session key from hex to bytes
    aesccm = AESCCM(key, tag_length=4)  # 4-byte authentication tag
    plaintext = aesccm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
