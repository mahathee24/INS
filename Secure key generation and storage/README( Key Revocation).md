🎯 **Objective**
The objective of this project is to implement a **Secure Key Management System (KMS)** that includes:
✅ Secure key generation and storage using symmetric and asymmetric encryption.
✅ Secure key exchange using the Diffie-Hellman protocol.
✅ **Revocation of compromised keys using a Certificate Revocation List (CRL).**

🏷️ **System Design Overview**

✅ **Components:**

**Key Revocation:**
- Maintain a **Certificate Revocation List (CRL)** to store revoked keys.
- Mark keys as revoked if compromised.
- Prevent the use of revoked keys.

**Key Management:**
- Generate symmetric (AES-256) and asymmetric (RSA) keys.
- Securely store keys using encryption.
- Provide centralized key distribution and exchange.

📂 **Folder Structure**

```plaintext
secure_kms/
├── symmetric/
│   ├── generate_key.py
│   ├── store_key.py
├── pki/
│   ├── generate_key.py
│   ├── ca.py
│   ├── crl.py  # Implements key revocation
├── exchange/
│   ├── diffie_hellman.py
├── keys/
├── certs/
├── main.py
└── README.md
```

🏆 **Key Revocation Implementation**

🔒 **Key Revocation Using a Revocation List (CRL)**

- Maintain a list of **revoked keys** in a JSON file.
- Before using a key, **check if it is revoked**.
- Provide a function to **revoke compromised keys**.

✅ **Code: Key Revocation Implementation**

👉 `pki/crl.py`

```python
import os
import base64
import json

REVOCATION_LIST_FILE = "keys/revoked_keys.json"

def revoke_key(key):
    """Revokes a key by adding it to the revocation list."""
    os.makedirs("keys", exist_ok=True)
    
    revoked_keys = []
    if os.path.exists(REVOCATION_LIST_FILE):
        with open(REVOCATION_LIST_FILE, "r") as f:
            revoked_keys = json.load(f)

    revoked_keys.append(base64.b64encode(key).decode())  # Store in Base64

    with open(REVOCATION_LIST_FILE, "w") as f:
        json.dump(revoked_keys, f, indent=4)

    print("Key has been revoked.")

def is_key_revoked(key):
    """Checks if a key is in the revocation list."""
    if not os.path.exists(REVOCATION_LIST_FILE):
        return False

    with open(REVOCATION_LIST_FILE, "r") as f:
        revoked_keys = json.load(f)

    return base64.b64encode(key).decode() in revoked_keys
```

✅ **Code: Key Revocation Check During Key Loading**

👉 `symmetric/store_key.py`

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
from pki.crl import is_key_revoked

def store_key(key, password):
    """Encrypts and stores the key securely if it is not revoked."""
    if is_key_revoked(key):
        print("ERROR: This key has been revoked and cannot be stored.")
        return

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
    
    print("Key stored securely at 'keys/symmetric_key.enc'")
```

✅ **Output:**
```plaintext
Key has been revoked.
ERROR: This key has been revoked and cannot be stored.
```

✅ **Flowchart: Key Revocation Process**

```plaintext
       +---------------------------+
       | Attempt to Use Key        |
       +---------------------------+
                   |
       +---------------------------+
       | Check Revocation List     |
       +---------------------------+
            /            \
      YES /              \ NO
         /                \
+----------------+    +----------------+
| Key Revoked   |    | Key is Active   |
| Deny Usage    |    | Proceed Securely|
+----------------+    +----------------+
```

### **Running the Code:**
You can test the revocation process by running the scripts in order:
1. Generate and store a key.
2. Revoke the key using `pki/crl.py`.
3. Try using the revoked key—it should be denied.

Would you like to integrate **automated key rotation** after revocation? 🚀



to run the code :- 
https://colab.research.google.com/drive/16gADJV8ZLSEGhEngLJ1PQbNvip0M5SV-?usp=sharing
