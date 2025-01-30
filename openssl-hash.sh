#!/bin/bash

# Variables for input file and private key
INPUT_FILE="testA"
PRIVATE_KEY="/home/genr8eofl/signing_key.priv"
PUBLIC_KEY="/home/genr8eofl/signing_key.priv.bak"

# Step 1: Generate SHA-512 hash of the file
echo "Hashing file: $INPUT_FILE"
openssl dgst -sha512 -binary "$INPUT_FILE" > hashfile.sha512

# Step 1a: Print the hash in hex format
echo "Hash in hex format:"
xxd -p hashfile.sha512

# Step 2: RSA sign the hash with your private key
echo "Signing the hash with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -in hashfile.sha512 -out signature.bin

# Step 3: Print the signature in hex format
echo "Signature in hex format:"
xxd -p signature.bin

# Step 4: Verify and recover the signature with the public key
echo "Verifying and recovering the original hash using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -inkey "$PUBLIC_KEY" -in signature.bin -out recovered_hash.bin

# Step 5: Display the recovered hash in hex format
echo "Recovered hash (in hex):"
xxd -p recovered_hash.bin

# Step 6: Compare the recovered hash with the original hash
echo "Comparing recovered hash with the original hash..."
if cmp -s hashfile.sha512 recovered_hash.bin; then
    echo "The recovered hash matches the original hash!"
else
    echo "The recovered hash does NOT match the original hash."
fi
