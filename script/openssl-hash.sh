#!/bin/bash
# openssl-hash-sign.sh v0.3 by genBTC 2025

# Variables for private key / public key
PRIVATE_KEY="/home/genr8eofl/signing_key.priv"      #contents: -----BEGIN PRIVATE KEY-----
PUBLIC_KEY="/home/genr8eofl/derived_public_key.pem" #contents: -----BEGIN PUBLIC KEY-----

# Variables for files (and tmp)
INPUT_FILE="testA"                       #A
hash_step0="$INPUT_FILE.sha512.bin"      #7a296f hash
dgst_step0="$INPUT_FILE.digest"          #"SHA2-512(testA)= 7a296f hash
sig_step2="$INPUT_FILE.sha512.sig2"      #020b68 sig
sig_step3="$INPUT_FILE.sha512.sig3"      #12d507 sig (recovers 7a296f)
step4="$INPUT_FILE.message4"             #7a296f hash
step6="$INPUT_FILE.sig6"                 #3af28d sig (recovers 7a296hash) - IMA
step7="$INPUT_FILE.sig7"                 #0919e5 recovers (3031300d0609garbagewhy)
step9="$INPUT_FILE.sig9"                 #48f348 sig (recovers 410a)
step8="$INPUT_FILE.message8"             #3031300d06096086480165030402010500042006f961b802bc46ee168555f066d28f4f0e9afdf3f88174c1ee6f9de004fc30a0
step10="$INPUT_FILE.message10"           #410a

# Step 0: Generate SHA-512 hash of the file
echo "Hashing file: $INPUT_FILE"
openssl dgst -sha512 -binary "$INPUT_FILE" > "${hash_step0}"
openssl dgst -sha512         "$INPUT_FILE" | tee "${dgst_step0}"

# Step 1: Print the hash (in hex format)
echo -n "Hash (hex):      "
xxd -p -c 64 "${hash_step0}"

echo "--------" #020b68
# Step 2: RSA sign the hash with your private key
echo "Signing the with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -digest sha512 -inkey "$PRIVATE_KEY" -rawin -in "${hash_step0}" -out "${sig_step2}"
# Step 2a: Print the signature (in hex format)
echo "Signature (hex):"
xxd -p -c 64 "${sig_step2}" # 020b68
# Step 2b: Verify will check the hash (sig in 12d507)
echo "Verifying signature, using original hash and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -digest sha512 -pubin -inkey "$PUBLIC_KEY" -rawin -in "${hash_step0}" -sigfile "${sig_step2}"

echo "--------" #12d507
# Step 3: RSA sign the hash with your private key
echo "Signing the Hash with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -in "${hash_step0}" -out "${sig_step3}"
# Step 3a: Print the signature (in hex format)
echo "Signature (hex):"
xxd -p -c 64 "${sig_step3}"     # 12d507
# Step 3b: Verify will check the hash (sig in 12d507)
echo "Verifying signature, using original hash and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify        -pubin -inkey "$PUBLIC_KEY" -in "${hash_step0}" -sigfile "${sig_step3}"
# Step 3c: Verify and recover the signature with the public key
echo "VerifyRecovering the original hash using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${sig_step3}" -out "${step4}"

# Step 4: Display the recovered hash in hex format (check first if -s is file non empty)
if [ -s "$step4" ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 "${step4}"
    # Compare the recovered hash with the original hash
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s "${hash_step0}" "${step4}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi

echo "--------" #3af28d
# Step 6: RSA sign the Message with your private key
echo "Signing the MESSAGE with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -digest sha512 -inkey "$PRIVATE_KEY" -rawin -in "${INPUT_FILE}" -out "${step6}"
# Step 6a: Print the signature (in hex format)
echo "Signature (hex):"
xxd -p -c 64 "${step6}"     # 3afd28
# Step 6b: Verify will check the hash
echo "Verifying signature, using original message and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -digest sha512 -pubin -inkey "$PUBLIC_KEY" -rawin -in "${INPUT_FILE}" -sigfile "${step6}"

echo "--------" #0919e58
# Step 7: RSA sign the Message with your private key
echo "Signing the Message File with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -rawin -in "${INPUT_FILE}" -out "${step7}"
# Step 7a: Print the signature (in hex format)
echo "Signature7 (hex):"
xxd -p -c 64 "${step7}"     # 0919e58
# Step 7b: Verify will check the hash
echo "Verifying signature, using original file and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -pubin -inkey "$PUBLIC_KEY" -rawin -in "${INPUT_FILE}" -sigfile "${step7}"
echo "VerifyRecovering the original file using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${step7}" -out "${step8}"

# Step 8: Display the recovered message in hex format (check first if -s is file non empty)
if [ -s "$step8" ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 "${step8}"
    # Compare the recovered hash with the original hash
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s "${step7}" "${step8}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi

echo "--------" #48f348
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
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${step9}" -out "${step10}"

# Step 10: Display the recovered message in hex format (check first if -s is file non empty)
if [ -s "$step10" ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 "${step10}"
    # Compare the recovered hash with the original hash
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s "${INPUT_FILE}" "${step10}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi

# Clean up?
#rm "${hash_step0}" "${sig_step3}" "${sig_step2}" "${step4}"
