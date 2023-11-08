from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Generate ECC keys
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Serialize and save the private key to a file
with open("private_key.pem", "wb") as f:
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    f.write(private_pem)

# Serialize and save the public key to a file
with open("public_key.pem", "wb") as f:
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    f.write(public_pem)
