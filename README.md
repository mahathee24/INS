# INS TASKS

Secure Key Management System (KMS) with Encryption, Key Exchange, and Revocation
📜 Overview
This project implements a Secure Key Management System (KMS) that ensures the secure generation, storage, exchange, and revocation of cryptographic keys. It supports both symmetric and asymmetric encryption, a Diffie-Hellman key exchange, and a certificate revocation system to manage compromised keys.

🚀 Features

✔ Centralized Key Distribution (Symmetric AES-256 Encryption)

✔ Public Key Infrastructure (PKI) (Asymmetric RSA Key Pair)

✔ Secure Key Exchange (Diffie-Hellman with HKDF)

✔ Key Revocation System (Certificate Revocation List - CRL)

📂 Folder Structure

    secure_kms/
    │── key_store.json          # Stores keys securely
    │── revoked_keys.json       # Stores revoked keys
    │── main.py                 # Main execution file
    │── README.md               # Project documentation

🔐 1. Centralized Key Distribution (Symmetric Encryption)

AES-256 symmetric keys are generated and stored securely.

Each key has an expiry time (default: 1 hour).

Expired keys are automatically invalidated.


🔹 Functions:

generate_symmetric_key() → Generates a 256-bit AES key.

store_symmetric_key(user_id, key, expiry_time=3600) → Stores the key securely in key_store.json.

is_key_expired(user_id) → Checks if the key is expired.


🔑 2. Public Key Infrastructure (Asymmetric Encryption)

Uses RSA-2048 keys for encryption and digital signatures.

Private keys are securely stored using PBKDF2-based encryption.

Public keys are stored in a centralized database.


🔹 Functions:

generate_asymmetric_keys() → Generates an RSA public-private key pair.

encrypt_private_key(private_key, password) → Encrypts the private key with a password.

decrypt_private_key(encrypted_key, salt, password) → Decrypts the private key when needed.

store_asymmetric_keys(user_id, private_key, public_key, password) → Saves encrypted private & public keys in key_store.json.



🔄 3. Secure Key Exchange (Diffie-Hellman Protocol)

Uses Diffie-Hellman (DH-2048) for secure key exchange.

Ensures that both parties generate the same shared secret without transmitting sensitive data.

Uses HKDF (HMAC-based Key Derivation Function) to derive a secure encryption key.


🔹 Functions:

generate_dh_parameters() → Generates Diffie-Hellman parameters.

generate_dh_private_key(parameters) → Generates a private key for DH.

compute_shared_secret(private_key, peer_public_key) → Computes a shared secret.

derive_key_from_secret(shared_secret) → Uses HKDF to derive a secure encryption key.


⛔ 4. Key Revocation System (CRL - Certificate Revocation List)

Compromised or expired keys can be revoked.

A revocation list (revoked_keys.json) is maintained.

The system rejects revoked keys during authentication.


🔹 Functions:

revoke_key(user_id) → Revokes the user's key.

is_key_revoked(user_id) → Checks if the key is revoked.


🏆 Execution & Testing

1️⃣ Run the script (main.py) and enter a user ID and password.

2️⃣ The system generates and stores symmetric & asymmetric keys.

3️⃣ Optionally, revoke a key and check if it's expired or revoked.

4️⃣ The final key store is displayed.


📌 Example Output

Enter the user ID: alice

Enter the password: mysecurepassword

Symmetric key stored for alice, expires in 3600 seconds

Asymmetric keys stored securely for alice

Keys Generated and Stored Securely:

Symmetric key (hashed): 938274982739472

Do you want to revoke keys? (yes/no): yes
 


Key revoked for alice

Key for alice has been revoked.

     Final Key Store State:
     {
    "alice": {
        "symmetric": {
            "key": "bG9uZ19yYW5kb21fZ2VuZXJhdGVkX2tleQ==",
            "expiry": 1714039200.0
        },
        "private": {
            "salt": "bG9uZ19yYW5kb21fc2FsdA==",
            "key": "ZW5jcnlwdGVkX3ByaXZhdGVfa2V5"
        },
        "public": "-----BEGIN PUBLIC KEY-----\n..."
    }
     }

🎯 Conclusion

🔹 This Secure Key Management System (KMS) ensures strong encryption, secure key exchange, and revocation.

🔹 It can be used in authentication, secure communications, and digital security applications.


To run the final code :- 
https://colab.research.google.com/drive/1lpzHQRyxT7KeB2g24Xi4LA9WAXmiHjPC?usp=sharing
