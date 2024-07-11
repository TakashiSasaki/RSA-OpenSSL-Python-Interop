# Script Name: rsautl_rsautl.py

import subprocess
import os

OPENSSL_PATH = r'C:\Program Files\Git\usr\bin\openssl.exe'

def generate_rsa_keys():
    # RSA鍵ペアの生成
    subprocess.run([OPENSSL_PATH, 'genpkey', '-algorithm', 'RSA', '-out', 'private_key.pem', '-pkeyopt', 'rsa_keygen_bits:2048'])
    subprocess.run([OPENSSL_PATH, 'rsa', '-pubout', '-in', 'private_key.pem', '-out', 'public_key.pem'])

def encrypt_message(message):
    # メッセージをファイルに書き込む
    with open('plaintext.txt', 'w') as f:
        f.write(message)
    
    # 公開鍵で暗号化
    subprocess.run([OPENSSL_PATH, 'rsautl', '-encrypt', '-inkey', 'public_key.pem', '-pubin', '-in', 'plaintext.txt', '-out', 'encrypted.bin'])

def decrypt_message():
    # 秘密鍵で復号
    subprocess.run([OPENSSL_PATH, 'rsautl', '-decrypt', '-inkey', 'private_key.pem', '-in', 'encrypted.bin', '-out', 'decrypted.txt'])
    
    # 復号されたメッセージを読み取る
    with open('decrypted.txt', 'r') as f:
        decrypted_message = f.read()
    
    return decrypted_message

def main():
    # 鍵ペアの生成
    generate_rsa_keys()
    
    # メッセージの暗号化
    message = "Hello"
    encrypt_message(message)
    
    # メッセージの復号
    decrypted_message = decrypt_message()
    
    # 結果の確認
    if message == decrypted_message:
        print("The message was successfully decrypted: ", decrypted_message)
    else:
        print("The decryption failed.")

    # 作業ファイルのクリーンアップ
    os.remove('private_key.pem')
    os.remove('public_key.pem')
    os.remove('plaintext.txt')
    os.remove('encrypted.bin')
    os.remove('decrypted.txt')

if __name__ == "__main__":
    main()
