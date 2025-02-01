#!/usr/bin/env python3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

privkey = "/home/genr8eofl/signing_key.priv"
pubkey = "/home/genr8eofl/derived_public_key.pem"
message = b"A\x0a"

# Load your RSA private key
#private_key_pem = b"""-----BEGIN PRIVATE KEY-----"""
# Load the RSA private key - from file
with open(privkey, "rb") as key_file:
    private_key_pem = key_file.read()
private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

# Optional 1) Message to hash (happens to be a hash)
hash = "7a296fab5364b34ce3e0476d55bf291bd41aa085e5ecf2a96883e593aa1836fed22f7242af48d54af18f55c8d1def13ec9314c926666a0ba63f7663500090565"
hash_bytes = bytes.fromhex(hash)
print("Input Hash(SHA512): ", hash_bytes.hex())

# Optional 2) Create the SHA512 hash of the message
sha512_hash = hashes.Hash(hashes.SHA512(), backend=default_backend())
sha512_hash.update(message)
digest = sha512_hash.finalize()
print("Digest Hash(SHA512):", digest.hex())

# Sign the MESSAGE  with the private key
signature = private_key.sign(
    message,    #//starts with 3af28d
    padding.PKCS1v15(),
    hashes.SHA512()
)
print("Signature(Hex):", signature.hex())

# Load your RSA Public key
#Public Verification
with open(pubkey, "rb") as key_file:
    public_key_pem = key_file.read()
public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

# Verify the signature of MESSAGE
try:
    public_key.verify(
        signature,
        message,    #verify message directly.
        padding.PKCS1v15(),
        hashes.SHA512()
    )
    print("Signature is valid.")
except Exception as e:
    print("Signature verification failed:", e)
#Signature is valid.

# Sign the hash  with the private key
signature = private_key.sign(
    digest,    #//starts with 020b68
    padding.PKCS1v15(),
    hashes.SHA512()
)
print("Signature(Hex):", signature.hex())

# Verify the signature of hash
try:
    public_key.verify(
        signature,
        hash_bytes,
        padding.PKCS1v15(),
        hashes.SHA512()
    )
    print("Signature is valid.")
except Exception as e:
    print("Signature verification failed:", e)
