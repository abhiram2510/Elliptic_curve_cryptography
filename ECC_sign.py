import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Generate ECC keys
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Serialize and save the private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open("private_key.pem", "wb") as f:
    f.write(private_pem)

# Serialize and save the public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("public_key.pem", "wb") as f:
    f.write(public_pem)

# Load the private key from a file (for signing and decryption)
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Load the public key from a file (for verifying signatures and encryption)
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

# Sign a message with the private key
def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

# Verify the signature of a message with the public key
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False

# Example usage
user_input = input("Enter a message: ")
message = user_input.encode("utf-8")

# Sign the message
signature = sign_message(private_key, message)

# Verify the signature
is_verified = verify_signature(public_key, message, signature)

if is_verified:
    print("Signature is verified: Message is authentic.")
else:
    print("Signature verification failed: Message may be tampered with.")

# Print the original message, signature, and verification result
print(f"Original Message: {message.decode()}")
print(f"Digital Signature: {signature}")
