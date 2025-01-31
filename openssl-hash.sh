#!/bin/bash
# openssl-hash-sign.sh by genBTC 2025

# Variables for private key / public key
PRIVATE_KEY="/home/genr8eofl/signing_key.priv"      #contents: -----BEGIN PRIVATE KEY-----
PUBLIC_KEY="/home/genr8eofl/derived_public_key.pem" #contents: -----BEGIN PUBLIC KEY-----

# Variables for files (and tmp)
INPUT_FILE="testA"
hash_step1a="$INPUT_FILE.sha512"
dgst_step1a="$INPUT_FILE.dgst"
hashstr_step1a="$INPUT_FILE.hash"
sig_step2="$INPUT_FILE.signature.bin"
sig_step2_raw="$INPUT_FILE.signature.raw"
step4="$INPUT_FILE.recovered_hash.bin"

# Step 0: Generate SHA-512 hash of the file
echo "Hashing file: $INPUT_FILE"
openssl dgst -sha512 -binary "$INPUT_FILE" > "${hash_step1a}"
openssl dgst -sha512         "$INPUT_FILE" | tee "${dgst_step1a}"

# Step 1: Print the hash (in hex format)
echo -n "Hash (hex):      "
xxd -p -c 64 "${hash_step1a}"

# Step 2: RSA sign the hash with your private key
echo "Signing the hash with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -digest sha512 -inkey "$PRIVATE_KEY" -rawin -in "${hash_step1a}" -out "${sig_step2_raw}"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -in "${hash_step1a}" -out "${sig_step2}"

# Step 3: Print the signature (in hex format)
echo "Signature (hex):"
#xxd -p -c 64 "${sig_step2}"    # 12d507
xxd -p -c 64 "${sig_step2_raw}" # 020b68

# Step 4: Verify and recover the signature with the public key
echo "VerifyRecovering the original hash using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "$sig_step2" -out "${step4}"

# Step 4a: Verify will recover the hash (sig becomes 12d507)
echo "Verifying again, the original hash using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -digest sha512 -pubin -inkey "$PUBLIC_KEY" -rawin -in "${hash_step1a}" -sigfile "${sig_step2_raw}"

# Step 5: Display the recovered hash in hex format (check first if -s is file non empty)
if [ -s "$step4" ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 "${step4}"

    # Step 6: Compare the recovered hash with the original hash
    echo "Comparing recovered hash with the original hash..."
    if cmp -s "${hash_step1a}" "${step4}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi

# Clean up?
#rm "${hash_step1a}" "${sig_step2}" "${sig_step2_raw}" "${step4}"
