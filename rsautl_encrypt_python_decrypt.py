# Script Name: rsautl_encrypt_python_decrypt.py

import subprocess
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

OPENSSL_PATH = r'C:\Program Files\Git\usr\bin\openssl.exe'

def generate_rsa_keys():
    print("Generating RSA keys using 'genpkey' and 'rsa' subcommands...")
    subprocess.run([OPENSSL_PATH, 'genpkey', '-algorithm', 'RSA', '-out', 'private_key.pem', '-pkeyopt', 'rsa_keygen_bits:2048'])
    print("Output: private_key.pem")
    subprocess.run([OPENSSL_PATH, 'rsa', '-pubout', '-in', 'private_key.pem', '-out', 'public_key.pem'])
    print("Output: public_key.pem")
    print("RSA keys generated.")

def encrypt_message(message):
    print("Encrypting message using 'rsautl' subcommand with PKCS#1 v1.5 padding...")
    with open('plaintext.txt', 'w') as f:
        f.write(message)
    print("Input: plaintext.txt")
    
    subprocess.run([OPENSSL_PATH, 'rsautl', '-encrypt', '-inkey', 'public_key.pem', '-pubin', '-in', 'plaintext.txt', '-out', 'encrypted.bin'])
    print("Output: encrypted.bin")
    print("Message encrypted.")

def decrypt_message_with_python():
    print("Decrypting message using Python with PKCS#1 v1.5 padding...")
    
    with open('private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    with open('encrypted.bin', 'rb') as enc_file:
        encrypted_message = enc_file.read()

    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.PKCS1v15()
    )

    print("Message decrypted.")
    return decrypted_message.decode()

def main():
    print("Starting RSA encryption with rsautl and decryption with Python...")
    
    generate_rsa_keys()
    
    message = "Hello"
    encrypt_message(message)
    
    decrypted_message = decrypt_message_with_python()
    
    if message == decrypted_message:
        print("The message was successfully decrypted: ", decrypted_message)
    else:
        print("The decryption failed.")
    
    print("Cleaning up temporary files...")
    os.remove('private_key.pem')
    os.remove('public_key.pem')
    os.remove('plaintext.txt')
    os.remove('encrypted.bin')
    print("Temporary files removed. Process completed.")

if __name__ == "__main__":
    main()
