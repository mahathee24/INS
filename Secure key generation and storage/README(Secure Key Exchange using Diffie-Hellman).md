Secure Key Exchange using Diffie-Hellman

🔒 How Diffie-Hellman Works:

Both parties generate a private key.
Compute a public key using the generator.
Exchange public keys.
Compute a shared secret using their private key and the other party's public key.


✅ Code: Diffie-Hellman Key Exchange

👉 exchange/diffie_hellman.py


    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.primitives import serialization

  # Generate Parameters
    parameters = dh.generate_parameters(generator=2, key_size=512)

# Generate Private Key
    private_key = parameters.generate_private_key()
    peer_private_key = parameters.generate_private_key()

# Exchange Public Keys
    public_key = private_key.public_key()
    peer_public_key = peer_private_key.public_key()

# Compute Shared Secret
    shared_secret = private_key.exchange(peer_public_key)
    print(f"Shared Secret: {shared_secret.hex()[:32]}")

✅ Output:

    Shared Secret: 8f4d3fcd7e8a231bcf1de6b7a9f2713d
✅ Flowchart: Diffie-Hellman Exchange
                       
     +---------+        +---------+
     |   Alice |        |   Bob   |
     +---------+        +---------+
     | Generate Private Key       |
     | Generate Public Key        |
     +---------+        +---------+
     | Exchange Public Keys |
     v                     v
    +---------+        +---------+
     | Compute Shared Secret     |
     +---------+        +---------+


🏆 3. Key Revocation (CRL)

🔒 How Revocation Works:

If a key is compromised, it’s added to the CRL.
The system rejects any communication using a revoked key.

✅ Code: Certificate Revocation List (CRL)
👉 pki/crl.py


    import json

    def revoke_key(key_id):
    crl = {}
    try:
        with open("certs/crl.json", "r") as f:
            crl = json.load(f)
    except FileNotFoundError:
        pass

    crl[key_id] = "revoked"

    with open("certs/crl.json", "w") as f:
        json.dump(crl, f, indent=4)

    print(f"Key {key_id} revoked")

    def is_revoked(key_id):
    try:
        with open("certs/crl.json", "r") as f:
            crl = json.load(f)
        return crl.get(key_id) == "revoked"
    except FileNotFoundError:
        return False

    if __name__ == "__main__":
    revoke_key("example-key-id")
    print(f"Key revoked: {is_revoked('example-key-id')}")
✅ Output:

    Key example-key-id revoked
    Key revoked: True
✅ Flowchart: Key Revocation

         +------------------------+
         | Key Compromise Detected|
         +------------------------+
                    |
         +------------------------+
         | Add to CRL             |
         +------------------------+
                    |
         +------------------------+
         | Reject Revoked Key     |
         +------------------------+


to run the code:- 
https://colab.research.google.com/drive/1pL5XZks0I1eVjh1FZHG1fQWgFPDzGOkU?usp=sharing
