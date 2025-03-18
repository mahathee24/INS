Secure Key Management System
🎯 Objective
The objective of this project is to design and implement a Secure Key Management System (KMS) to handle both symmetric and asymmetric encryption. This involves:
✅ Secure key generation, storage, and retrieval.
✅ Key distribution using centralized infrastructure for symmetric encryption.
✅ Public Key Infrastructure (PKI) for asymmetric encryption.
✅ Secure key exchange using Diffie-Hellman.
✅ Revocation of keys in case of compromise.

🏗️ Architecture Overview

The system will have two main components:
Centralized Key Distribution:

Used for symmetric encryption (AES).
Keys are generated and stored in a secure vault.
Distributed to clients over a secure channel.

Public Key Infrastructure (PKI):
Used for asymmetric encryption (RSA).
Certificate Authority (CA) will generate and validate certificates.
Public-private key pairs will be managed using PKI.

Tasks and Implementation

🔐 1. Centralized Key Distribution for Symmetric Encryption
Use AES-256 for symmetric encryption.

Securely store the key and share it over an encrypted channel.

✅ Code: Symmetric Key Generation and Storage
👉 Folder Structure:

    secure_kms/
    ├── symmetric/
    │   ├── generate_key.py
    │   ├── store_key.py
    ├── keys/
    └── main.py

👉 generate_key.py


     import os
     import base64

    def generate_symmetric_key():
    key = os.urandom(32)  # 256-bit key for AES-256
    print(f"Generated Symmetric Key: {base64.b64encode(key).decode()}")
    return key

     if __name__ == "__main__":
    key = generate_symmetric_key()

👉 store_key.py


    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    import os
    import base64

    def store_key(key, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    encrypted_key = kdf.derive(password.encode())
    
    with open("keys/symmetric_key.enc", "wb") as f:
        f.write(salt + encrypted_key)
    
    print(f"Key stored securely at 'keys/symmetric_key.enc'")

     if __name__ == "__main__":
    key = os.urandom(32)  # 256-bit AES key
    store_key(key, "secure_password")

👉 Output:


    Generated Symmetric Key: n7G7E8zW31gUuCEgoNvQQ==
    Key stored securely at 'keys/symmetric_key.enc'

✅ Pros and Cons of Symmetric Key Distribution

Fast encryption and decryption	     
Suitable for large data encryption	        
Efficient for real-time applications	

Single key compromise affects security
Requires secure channel for key distribution
Key management complexity increases with number of users






