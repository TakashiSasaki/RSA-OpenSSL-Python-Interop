# Script Name: padding_mismatch_test.py

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

def encrypt_message(message, padding):
    print(f"Encrypting message using 'rsautl' subcommand with {padding} padding...")
    with open('plaintext.txt', 'w') as f:
        f.write(message)
    print("Input: plaintext.txt")
    
    if padding == 'oaep':
        subprocess.run([OPENSSL_PATH, 'rsautl', '-encrypt', '-inkey', 'public_key.pem', '-pubin', '-oaep', '-in', 'plaintext.txt', '-out', 'encrypted.bin'])
    else:
        subprocess.run([OPENSSL_PATH, 'rsautl', '-encrypt', '-inkey', 'public_key.pem', '-pubin', '-in', 'plaintext.txt', '-out', 'encrypted.bin'])
    
    print("Output: encrypted.bin")
    print("Message encrypted.")

def decrypt_message(padding):
    print(f"Decrypting message using 'rsautl' subcommand with {padding} padding...")
    print("Input: encrypted.bin")
    
    if padding == 'oaep':
        result = subprocess.run([OPENSSL_PATH, 'rsautl', '-decrypt', '-inkey', 'private_key.pem', '-oaep', '-in', 'encrypted.bin', '-out', 'decrypted.txt'], capture_output=True, text=True)
    else:
        result = subprocess.run([OPENSSL_PATH, 'rsautl', '-decrypt', '-inkey', 'private_key.pem', '-in', 'encrypted.bin', '-out', 'decrypted.txt'], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Decryption failed: {result.stderr}")
        return None
    
    print("Output: decrypted.txt")
    with open('decrypted.txt', 'r') as f:
        decrypted_message = f.read()
    
    print("Message decrypted.")
    return decrypted_message

def main():
    print("Starting RSA encryption and decryption process with padding mismatch...")
    
    generate_rsa_keys()
    
    message = "Hello"
    
    # Encrypt with PKCS#1 v1.5 padding and decrypt with OAEP padding
    encrypt_message(message, padding='pkcs1')
    decrypted_message = decrypt_message(padding='oaep')
    
    if decrypted_message is None:
        print("Decryption failed due to padding mismatch.")
    elif message == decrypted_message:
        print("The message was successfully decrypted: ", decrypted_message)
    else:
        print("The decryption failed.")
    
    # Encrypt with OAEP padding and decrypt with PKCS#1 v1.5 padding
    encrypt_message(message, padding='oaep')
    decrypted_message = decrypt_message(padding='pkcs1')
    
    if decrypted_message is None:
        print("Decryption failed due to padding mismatch.")
    elif message == decrypted_message:
        print("The message was successfully decrypted: ", decrypted_message)
    else:
        print("The decryption failed.")
    
    print("Cleaning up temporary files...")
    os.remove('private_key.pem')
    os.remove('public_key.pem')
    os.remove('plaintext.txt')
    os.remove('encrypted.bin')
    if os.path.exists('decrypted.txt'):
        os.remove('decrypted.txt')
    print("Temporary files removed. Process completed.")

if __name__ == "__main__":
    main()
