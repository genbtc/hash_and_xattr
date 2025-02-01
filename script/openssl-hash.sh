#!/bin/bash
# openssl-hash-sign.sh v0.3 by genBTC 2025

# Variables for private key / public key
PRIVATE_KEY="/home/genr8eofl/signing_key.priv"      #contents: -----BEGIN PRIVATE KEY-----
PUBLIC_KEY="/home/genr8eofl/derived_public_key.pem" #contents: -----BEGIN PUBLIC KEY-----

# Variables for files (and tmp)
INPUT_FILE="testA"                    #A
hash_step0="$INPUT_FILE.sha512.bin"   #7a296f hash
dgst_step0="$INPUT_FILE.digest"       #"SHA2-512(testA)= 7a296f hash
step1="$INPUT_FILE.sha512.sig1"       #020b68 sig
step1d="$INPUT_FILE.message1"         #3051300d060960864801650304020305000440803305d4248ff306420053d133d217339f8dafcd96b70e1e6e8f56115f12e130edd2cea1e073fda86f00995511d50698737e7eb895096533a8b0231c15d88907
step3="$INPUT_FILE.sha512.sig3"       #12d507 sig (recovers 7a296f)
step3d="$INPUT_FILE.message3"         #3051300d060960864801650304020305000440803305d4248ff306420053d133d217339f8dafcd96b70e1e6e8f56115f12e130edd2cea1e073fda86f00995511d50698737e7eb895096533a8b0231c15d88907 why
step5="$INPUT_FILE.sig5"              #3af28d sig (recovers 7a296hash) - IMA
step5d="$INPUT_FILE.message5"         #3051300d0609608648016503040203050004407a296fab5364b34ce3e0476d55bf291bd41aa085e5ecf2a96883e593aa1836fed22f7242af48d54af18f55c8d1def13ec9314c926666a0ba63f7663500090565 why
step9="$INPUT_FILE.sig9"              #48f348 sig (recovers 410a)
step9d="$INPUT_FILE.message9"         #410a = A

# Step 0: Generate SHA-512 hash of the file
echo "Hashing file: $INPUT_FILE"
openssl dgst -sha512 -binary "$INPUT_FILE" > "${hash_step0}"
openssl dgst -sha512         "$INPUT_FILE" | tee "${dgst_step0}"
# Step 0: Print the hash (in hex format)
echo -n "Hash (hex):      "
xxd -p -c 64 "${hash_step0}"

echo "--------Raw" #020b68
# Step 1: RSA sign the hash with your private key
echo "Signing the with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -digest sha512 -inkey "$PRIVATE_KEY" -rawin -in "${hash_step0}" -out "${step1}"
# Step 1a: Print the signature (in hex format)
echo "Signature1 (hex):"
xxd -p -c 64 "${step1}" # 020b68
# Step 1b: Verify will check the hash (sig in 12d507)
echo "Verifying signature, using original hash and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -digest sha512 -pubin -inkey "$PUBLIC_KEY" -rawin -in "${hash_step0}" -sigfile "${step1}"
# Step 1c: Verify and recover the signature with the public key
echo "VerifyRecovering the original hash using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${step1}" -out "${step1d}"
# Step 1d: Display the recovered hash in hex format (check first if -s is file non empty)
if [ -s "$step1d" ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 "${step1d}"
    # Compare the recovered hash with the original hash
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s "${hash_step0}" "${step1d}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi
#Does not match

echo "--------Raw" #3af28d
# Step 5: RSA sign the Message with your private key
echo "Signing the MESSAGE with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -digest sha512 -inkey "$PRIVATE_KEY" -rawin -in "${INPUT_FILE}" -out "${step5}"
# Step 5a: Print the signature (in hex format)
echo "Signature5 (hex):"
xxd -p -c 64 "${step5}"     # 3afd28
# Step 5b: Verify will check the hash
echo "Verifying signature, using original message and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -digest sha512 -pubin -inkey "$PUBLIC_KEY" -rawin -in "${INPUT_FILE}" -sigfile "${step5}"
echo "VerifyRecovering the original file using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${step5}" -out "${step5d}"
# Step 5c: Display the recovered message in hex format (check first if -s is file non empty)
if [ -s "$step5d" ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 "${step5d}"
    # Compare the recovered hash with the original hash
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s "${step5}" "${step5d}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi


echo "--------Valid" #12d507
# Step 3: RSA sign the hash with your private key
echo "Signing the Hash with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -in "${hash_step0}" -out "${step3}"
# Step 3a: Print the signature (in hex format)
echo "Signature3 (hex):"
xxd -p -c 64 "${step3}"     # 12d507
# Step 3b: Verify will check the hash (sig in 12d507)
echo "Verifying signature, using original hash and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify        -pubin -inkey "$PUBLIC_KEY" -in "${hash_step0}" -sigfile "${step3}"
# Step 3c: Verify and recover the signature with the public key
echo "VerifyRecovering the original hash using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${step3}" -out "${step3d}"
# Step 3d4: Display the recovered hash in hex format (check first if -s is file non empty)
if [ -s "$step3d" ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 "${step3d}"
    # Compare the recovered hash with the original hash
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s "${hash_step0}" "${step3d}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi

echo "--------Valid" #48f348
# Step 9: RSA sign the Message with your private key
echo "Signing the Message File with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -in "${INPUT_FILE}" -out "${step9}"
# Step 9a: Print the signature (in hex format)
echo "Signature9 (hex):"
xxd -p -c 64 "${step9}"     # 48f348
# Step 9b: Verify will check the hash
echo "Verifying signature, using original file and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -pubin -inkey "$PUBLIC_KEY" -in "${INPUT_FILE}" -sigfile "${step9}"
echo "VerifyRecovering the original file using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${step9}" -out "${step9d}"
# Step 9c10: Display the recovered message in hex format (check first if -s is file non empty)
if [ -s "$step9d" ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 "${step9d}"
    # Compare the recovered hash with the original hash
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s "${INPUT_FILE}" "${step9d}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi

# Clean up?
#rm "${hash_step0}" "${step3}" "${step1}" "${step3d}"
#rm ${INPUT_FILE}.*
