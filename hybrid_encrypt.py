from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.backends import default_backend
import os

# Load RSA public key from PEM file
def load_rsa_public_key(pem_path):
    with open(pem_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

# Encrypt AES key with RSA public key using SHA1 for compatibility with mbedTLS
def encrypt_aes_key_rsa(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),  # ← changed here
            algorithm=hashes.SHA1(),                         # ← and here
            label=None
        )
    )
    return encrypted_key

# Encrypt file content using AES-CBC
def encrypt_data_aes(plaintext, aes_key, iv):
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Main
def main():
    # Read input.txt
    with open("delta_config.cfg", "rb") as f:
        plaintext = f.read()

    # Generate AES key (256-bit) and IV (128-bit)
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # Encrypt data with AES
    ciphertext = encrypt_data_aes(plaintext, aes_key, iv)

    # Load RSA public key
    public_key = load_rsa_public_key("public.pem")

    # Encrypt AES key with RSA (using SHA1)
    encrypted_aes_key = encrypt_aes_key_rsa(aes_key, public_key)

    # Final output: [RSA_AES_KEY_SIZE (2 bytes)][RSA_AES_KEY][IV][AES_CIPHERTEXT]
    with open("delta_config.enc", "wb") as out:
        out.write(len(encrypted_aes_key).to_bytes(2, byteorder='big'))  # key size
        out.write(encrypted_aes_key)
        out.write(iv)
        out.write(ciphertext)

    print("[+] Hybrid encryption completed and saved to output.enc")

if __name__ == "__main__":
    main()
