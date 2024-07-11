# Script Name: rsautl_pkeyutl.py

import subprocess
import os

OPENSSL_PATH = r'C:\Program Files\Git\usr\bin\openssl.exe'

def generate_rsa_keys():
    print("Generating RSA keys using 'genpkey' and 'rsa' subcommands...")
    subprocess.run([OPENSSL_PATH, 'genpkey', '-algorithm', 'RSA', '-out', 'private_key.pem', '-pkeyopt', 'rsa_keygen_bits:2048'])
    print("Output: private_key.pem")
    subprocess.run([OPENSSL_PATH, 'rsa', '-pubout', '-in', 'private_key.pem', '-out', 'public_key.pem'])
    print("Output: public_key.pem")
    print("RSA keys generated.")

def encrypt_message(message):
    print("Encrypting message using 'rsautl' subcommand...")
    with open('plaintext.txt', 'w') as f:
        f.write(message)
    print("Input: plaintext.txt")
    
    subprocess.run([OPENSSL_PATH, 'rsautl', '-encrypt', '-inkey', 'public_key.pem', '-pubin', '-in', 'plaintext.txt', '-out', 'encrypted.bin'])
    print("Output: encrypted.bin")
    print("Message encrypted.")

def decrypt_message():
    print("Decrypting message using 'pkeyutl' subcommand...")
    print("Input: encrypted.bin")
    subprocess.run([OPENSSL_PATH, 'pkeyutl', '-decrypt', '-inkey', 'private_key.pem', '-in', 'encrypted.bin', '-out', 'decrypted.txt'])
    print("Output: decrypted.txt")
    
    with open('decrypted.txt', 'r') as f:
        decrypted_message = f.read()
    
    print("Message decrypted.")
    return decrypted_message

def main():
    print("Starting RSA encryption and decryption process using rsautl and pkeyutl...")
    
    generate_rsa_keys()
    
    message = "Hello"
    encrypt_message(message)
    
    decrypted_message = decrypt_message()
    
    if message == decrypted_message:
        print("The message was successfully decrypted: ", decrypted_message)
    else:
        print("The decryption failed.")
    
    print("Cleaning up temporary files...")
    os.remove('private_key.pem')
    os.remove('public_key.pem')
    os.remove('plaintext.txt')
    os.remove('encrypted.bin')
    os.remove('decrypted.txt')
    print("Temporary files removed. Process completed.")

if __name__ == "__main__":
    main()
