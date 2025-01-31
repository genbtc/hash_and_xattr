#!/bin/bash
# openssl-hash-sign.sh by genBTC 2025

# Variables for private key / public key
PRIVATE_KEY="/home/genr8eofl/signing_key.priv"      #contents: -----BEGIN PRIVATE KEY-----
PUBLIC_KEY="/home/genr8eofl/derived_public_key.pem" #contents: -----BEGIN PUBLIC KEY-----

# Variables for files (and tmp)
INPUT_FILE="testA"                          #A
hash_step0="$INPUT_FILE.sha512.bin"         #7a296
dgst_step0="$INPUT_FILE.dgst"               #SHA2-512(testA)= 7a296
sig_step2="$INPUT_FILE.signature.bin"       #12d507
sig_step2_raw="$INPUT_FILE.signature.raw"   #020b68
step4="$INPUT_FILE.recovered"               #A

# Step 0: Generate SHA-512 hash of the file
echo "Hashing file: $INPUT_FILE"
openssl dgst -sha512 -binary "$INPUT_FILE" > "${hash_step0}"
openssl dgst -sha512         "$INPUT_FILE" | tee "${dgst_step0}"

# Step 1: Print the hash (in hex format)
echo -n "Hash (hex):      "
xxd -p -c 64 "${hash_step0}"

# Step 2: RSA sign the hash with your private key
echo "Signing the hash with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -digest sha512 -inkey "$PRIVATE_KEY" -rawin -in "${hash_step0}" -out "${sig_step2_raw}"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -in "${hash_step0}" -out "${sig_step2}"

# Step 3: Print the signature (in hex format)
echo "Signature (hex):"
xxd -p -c 64 "${sig_step2}"     # 12d507
echo "Signature (raw):"
xxd -p -c 64 "${sig_step2_raw}" # 020b68

# Step 4a: Verify will check the hash (sig in 12d507)
echo "Verifying signature, using original hash and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -digest sha512 -pubin -inkey "$PUBLIC_KEY" -rawin -in "${hash_step0}" -sigfile "${sig_step2_raw}"

# Step 4: Verify and recover the signature with the public key
echo "VerifyRecovering the original hash using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "$sig_step2" -out "${step4}"

# Step 5: Display the recovered hash in hex format (check first if -s is file non empty)
if [ -s "$step4" ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 "${step4}"

    # Step 6: Compare the recovered hash with the original hash
    echo "Comparing recovered hash with the original hash..."
    if cmp -s "${hash_step0}" "${step4}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi

# Clean up?
#rm "${hash_step0}" "${sig_step2}" "${sig_step2_raw}" "${step4}"
