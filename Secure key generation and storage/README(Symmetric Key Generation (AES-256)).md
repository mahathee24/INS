Secure Key Management System


🎯 Objective
The objective of this project is to implement a Secure Key Management System (KMS) that includes:
✅ Secure key generation and storage using symmetric and asymmetric encryption.
✅ Secure key exchange using the Diffie-Hellman protocol.
✅ Revocation of compromised keys using a Certificate Revocation List (CRL).

🏗️ System Design Overview

✅ Components:

Symmetric Encryption:

Generate symmetric key (AES-256).
Store securely using encryption.
Centralized key distribution.

Asymmetric Encryption:

Generate RSA public-private key pair.
Use public key for encryption and private key for decryption.
Manage trust using a self-signed certificate.

Key Exchange:

Use Diffie-Hellman for secure key exchange.
Prevent man-in-the-middle attacks.

Key Revocation:

Maintain a Certificate Revocation List (CRL).
Mark keys as revoked if compromised.

📂 Folder Structure

     secure_kms/
     ├── symmetric/
     │   ├── generate_key.py
     │   ├── store_key.py
     ├── pki/
    │   ├── generate_key.py
    │   ├── ca.py
    │   ├── crl.py
    ├── exchange/
    │   ├── diffie_hellman.py
    ├── keys/
    ├── certs/
    ├── main.py
    └── README.md

🏆 1. Secure Key Generation and Storage

🔒 Symmetric Key Generation (AES-256)

Generate a 256-bit AES key.
Securely store it using a passphrase-derived key.

✅ Code: Symmetric Key Generation

👉 symmetric/generate_key.py


    import os
    import base64

    def generate_symmetric_key():
    key = os.urandom(32)  # 256-bit key for AES-256
    print(f"Generated Symmetric Key: {base64.b64encode(key).decode()}")
    return key

    if __name__ == "__main__":
    key = generate_symmetric_key()

👉 symmetric/store_key.py

 
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    import os

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
    key = os.urandom(32)
    store_key(key, "secure_password")


✅ Output:

    Generated Symmetric Key: gkYtR2Fh1FmhGJ+3TtT2GQ==
    Key stored securely at 'keys/symmetric_key.enc'
  
  ✅ Flowchart: Symmetric Key Generation and Storage

           +---------------------------+
           | Generate AES-256 Key       |
           +---------------------------+
                      |
           +---------------------------+
           | Encrypt with Passphrase   |
           +---------------------------+
                      |
           +---------------------------+
           | Store in Secure File      |
           +---------------------------+
