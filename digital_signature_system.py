# Digital Signature Verifier in Python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
# -----------------------------
# Step 1: Generate RSA Key Pair
# -----------------------------
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Save keys to files (optional)
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
# -----------------------------
# Step 2: Create Message
# -----------------------------
message = b"Hello, this is a secret message from Mansi!"
# -----------------------------
# Step 3: Hash the Message
# -----------------------------
digest = hashes.Hash(hashes.SHA256())
digest.update(message)
hashed_message = digest.finalize()
# -----------------------------
# Step 4: Sign the Message
# -----------------------------
signature = private_key.sign(
    hashed_message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Digital Signature:", signature.hex())
# -----------------------------
# Step 5: Verify the Signature
# -----------------------------
try:
    public_key.verify(
        signature,
        hashed_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Verification Successful! Signature is valid.")
except Exception as e:
    print("Verification Failed!", e)