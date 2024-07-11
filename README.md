# README.md

## Overview

This repository contains several Python scripts that demonstrate RSA encryption and decryption using both OpenSSL and the `cryptography` library in Python. The scripts cover various scenarios, including using different padding schemes and verifying compatibility between OpenSSL and Python implementations.

## Requirements

- Python 3.x
- OpenSSL installed and accessible via the specified path in the scripts
- `cryptography` library for Python

## Installation

1. **Install Python:**
   Ensure Python 3.x is installed on your system. You can download it from the [official Python website](https://www.python.org/downloads/).

2. **Install OpenSSL:**
   Ensure OpenSSL is installed and accessible at the specified path. If not, download and install it from the [OpenSSL website](https://www.openssl.org/source/).

3. **Install `cryptography` library:**
   Use pip to install the required `cryptography` library:
   ```sh
   pip install cryptography
   ```

## Scripts Description

### 1. padding_mismatch_test.py

**Description:**
This script demonstrates the issues that arise when different padding schemes are used for encryption and decryption. It encrypts a message with one padding scheme (PKCS#1 v1.5 or OAEP) and attempts to decrypt it with a different padding scheme.

**Usage:**
```sh
python padding_mismatch_test.py
```

### 2. pkeyutl_encrypt_python_decrypt.py

**Description:**
This script generates RSA key pairs using OpenSSL, encrypts a message using OpenSSL's `pkeyutl` subcommand, and decrypts it using Python's `cryptography` library.

**Usage:**
```sh
python pkeyutl_encrypt_python_decrypt.py
```

### 3. pkeyutl_pkeyutl.py

**Description:**
This script uses OpenSSL's `pkeyutl` subcommand for both encryption and decryption. It ensures that the encrypted message can be decrypted correctly using the same tool.

**Usage:**
```sh
python pkeyutl_pkeyutl.py
```

### 4. pkeyutl_rsautl.py

**Description:**
This script encrypts a message using OpenSSL's `pkeyutl` subcommand and decrypts it using OpenSSL's `rsautl` subcommand.

**Usage:**
```sh
python pkeyutl_rsautl.py
```

### 5. python_encrypt_pkeyutl_decrypt.py

**Description:**
This script generates RSA key pairs using Python's `cryptography` library, encrypts a message using Python, and decrypts it using OpenSSL's `pkeyutl` subcommand.

**Usage:**
```sh
python python_encrypt_pkeyutl_decrypt.py
```

### 6. python_encrypt_rsautl_decrypt.py

**Description:**
This script generates RSA key pairs using Python's `cryptography` library, encrypts a message using Python, and decrypts it using OpenSSL's `rsautl` subcommand.

**Usage:**
```sh
python python_encrypt_rsautl_decrypt.py
```

### 7. rsautl_encrypt_python_decrypt.py

**Description:**
This script generates RSA key pairs using OpenSSL, encrypts a message using OpenSSL's `rsautl` subcommand, and decrypts it using Python's `cryptography` library.

**Usage:**
```sh
python rsautl_encrypt_python_decrypt.py
```

### 8. rsautl_pkeyutl.py

**Description:**
This script encrypts a message using OpenSSL's `rsautl` subcommand and decrypts it using OpenSSL's `pkeyutl` subcommand.

**Usage:**
```sh
python rsautl_pkeyutl.py
```

### 9. rsautl_rsautl.py

**Description:**
This script uses OpenSSL's `rsautl` subcommand for both encryption and decryption. It ensures that the encrypted message can be decrypted correctly using the same tool.

**Usage:**
```sh
python rsautl_rsautl.py
```

## Notes

- Ensure that the OpenSSL path is correctly set in the scripts. Modify the `OPENSSL_PATH` variable if necessary.
- The scripts use PKCS#1 v1.5 padding for both encryption and decryption, unless specified otherwise. Ensure this padding scheme is used consistently to avoid decryption errors.
- Temporary files (e.g., `private_key.pem`, `public_key.pem`, `plaintext.txt`, `encrypted.bin`, `decrypted.txt`) are created during execution and cleaned up afterward. Ensure you have write permissions in the script's directory.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Python Cryptography Library](https://cryptography.io/)
- [OpenSSL](https://www.openssl.org/)

This README provides detailed instructions on the requirements, installation, script usage, and notes to help you understand and execute the scripts successfully.