# Script Name: python_encrypt_pkeyutl_decrypt.py

import subprocess
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

OPENSSL_PATH = r'C:\Program Files\Git\usr\bin\openssl.exe'

def generate_rsa_keys():
    print("Generating RSA keys using 'cryptography' library...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save private key
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("Output: private_key.pem")

    # Save public key
    with open('public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Output: public_key.pem")
    print("RSA keys generated.")

def encrypt_message(message):
    print("Encrypting message using 'cryptography' library with PKCS#1 v1.5 padding...")
    
    with open('public_key.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.PKCS1v15()
    )

    with open('encrypted.bin', 'wb') as f:
        f.write(encrypted_message)
    print("Output: encrypted.bin")
    print("Message encrypted.")

def decrypt_message_with_pkeyutl():
    print("Decrypting message using 'pkeyutl' subcommand with PKCS#1 v1.5 padding...")
    print("Input: encrypted.bin")
    
    result = subprocess.run([OPENSSL_PATH, 'pkeyutl', '-decrypt', '-inkey', 'private_key.pem', '-in', 'encrypted.bin', '-out', 'decrypted.txt'], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Decryption failed: {result.stderr}")
        return None
    
    print("Output: decrypted.txt")
    with open('decrypted.txt', 'r') as f:
        decrypted_message = f.read()
    
    print("Message decrypted.")
    return decrypted_message

def main():
    print("Starting RSA encryption with Python and decryption with pkeyutl...")
    
    generate_rsa_keys()
    
    message = "Hello"
    encrypt_message(message)
    
    decrypted_message = decrypt_message_with_pkeyutl()
    
    if message == decrypted_message:
        print("The message was successfully decrypted: ", decrypted_message)
    else:
        print("The decryption failed.")
    
    print("Cleaning up temporary files...")
    os.remove('private_key.pem')
    os.remove('public_key.pem')
    os.remove('encrypted.bin')
    if os.path.exists('decrypted.txt'):
        os.remove('decrypted.txt')
    print("Temporary files removed. Process completed.")

if __name__ == "__main__":
    main()
