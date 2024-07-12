import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Load the RSA key from the file
with open("rsa_key.json", "r") as file:
    rsa_key_data = json.load(file)

# Load the ciphertext from the file
with open("encrypted_key.json", "r") as file:
    ciphertext = json.load(file)

# Convert ciphertext to bytes
ciphertext_bytes = bytes(ciphertext)

# Function to decode Base64URL to integer
def base64url_to_int(data):
    return int.from_bytes(base64.urlsafe_b64decode(data + '=='), 'big')

# Convert the JWK to an RSA private key
private_key = rsa.RSAPrivateNumbers(
    p=base64url_to_int(rsa_key_data["p"]),
    q=base64url_to_int(rsa_key_data["q"]),
    d=base64url_to_int(rsa_key_data["d"]),
    dmp1=base64url_to_int(rsa_key_data["dp"]),
    dmq1=base64url_to_int(rsa_key_data["dq"]),
    iqmp=base64url_to_int(rsa_key_data["qi"]),
    public_numbers=rsa.RSAPublicNumbers(
        e=base64url_to_int(rsa_key_data["e"]),
        n=base64url_to_int(rsa_key_data["n"])
    )
).private_key(default_backend())

# Decrypt the ciphertext using SHA1
try:
    plaintext = private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    decrypted_text_integers = list(plaintext)
    decrypted_text_base64url = base64.urlsafe_b64encode(plaintext).decode('utf-8')
except ValueError as e:
    decrypted_text_integers = "Decryption failed: " + str(e)
    decrypted_text_base64url = "Decryption failed: " + str(e)

print("Decrypted text (integers):", decrypted_text_integers)
print("Decrypted text (base64url):", decrypted_text_base64url)
