Public Key Infrastructure (PKI) for Asymmetric Encryption


Use RSA-2048 for asymmetric encryption.
Generate a public-private key pair.
Create a self-signed certificate to establish trust.
Clients use the public key for encryption, private key for decryption.

✅ Code: Asymmetric Key Generation and Certificate Authority

👉 Folder Structure:


    secure_kms/
    ├── pki/
    │   ├── generate_key.py
    │   ├── ca.py
    ├── certs/
    └── main.py

👉 generate_key.py


    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    def generate_asymmetric_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Store Private Key
    with open("certs/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Store Public Key
    with open("certs/public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Asymmetric keys generated and stored securely")

    if __name__ == "__main__":
    generate_asymmetric_key()

👉 Output:
Asymmetric keys generated and stored securely

✅ Flowchart: Asymmetric Key Exchange

              +--------------------------+
              | RSA Key Generator        |
              +--------------------------+
                         |
              +--------------------------+
              | Private Key (CA)         |
              +--------------------------+
                         |
              +--------------------------+
              | Public Key Distribution  |
              +--------------------------+
                         |
              +--------------------------+
              | Client Uses Public Key   |
              +--------------------------+



Folder Structure Overview

    secure_kms/
    ├── symmetric/             # Symmetric key generation and storage
    ├── pki/                   # Asymmetric key generation and PKI
    ├── keys/                  # Stores symmetric keys
    ├── certs/                 # Stores public and private keys
    ├── main.py                # Main program
    └── README.md


🏆 Advantages of This System

✔️ Secure key generation and storage

✔️ Fast encryption with symmetric keys

✔️ Secure exchange using asymmetric keys

✔️ Protection against man-in-the-middle attacks with Diffie-Hellman



run the code :-  

https://colab.research.google.com/drive/1uCdbrClH-UUdaQD4xKJyacp8_yKxH2fE?usp=sharing
