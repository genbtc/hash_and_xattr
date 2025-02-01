#!/bin/bash
# openssl-hash-sign.sh v0.34 by genBTC 2025

# Variables for private key / public key
PRIVATE_KEY="/home/genr8eofl/signing_key.priv"      #contents: -----BEGIN PRIVATE KEY-----
PUBLIC_KEY="/home/genr8eofl/derived_public_key.pem" #contents: -----BEGIN PUBLIC KEY-----

# Variables for files (and tmp)
INPUT_FILE="testA"                    #A + LineFeed
hash_step0="$INPUT_FILE.sha512.bin"   #7a296f... hash bytes (has bin.sig same as .sig and .sig2
dgst_step0="$INPUT_FILE.digest"       #"SHA2-512(testA)= 7a296f hash digest
step1="$INPUT_FILE.sig1"              #020b68 sig (recovers                 80 33 05 )
step1d="$INPUT_FILE.message1"         #3051300d060960864801650304020305000440803305d4248ff306420053d133d217339f8dafcd96b70e1e6e8f56115f12e130edd2cea1e073fda86f00995511d50698737e7eb895096533a8b0231c15d88907
step2="$INPUT_FILE.sig2"              #3af28d sig (recovers raw digest with  7a296f) - IMA # $ openssl dgst -sha512 -sign -bin
step2d="$INPUT_FILE.message2"         #3051300d0609608648016503040203050004407a296fab5364b34ce3e0476d55bf291bd41aa085e5ecf2a96883e593aa1836fed22f7242af48d54af18f55c8d1def13ec9314c926666a0ba63f7663500090565 why
step3="$INPUT_FILE.sig3"              #12d507 sig (recovers 7a296f)
step3d="$INPUT_FILE.message3"         #7a296fab5364b34ce3e0476d55bf291bd41aa085e5ecf2a96883e593aa1836fed22f7242af48d54af18f55c8d1def13ec9314c926666a0ba63f7663500090565
step4="$INPUT_FILE.sig4"              #48f348 sig (recovers 410a)
step4d="$INPUT_FILE.message4"         #410a = A + LineFeed

# Step 0: Generate SHA-512 hash of the file
echo "Hashing file: $INPUT_FILE"
openssl dgst -sha512 -binary "$INPUT_FILE" > "${hash_step0}"
openssl dgst -sha512         "$INPUT_FILE" | tee "${dgst_step0}"
# Step 0: Print the hash (in hex format)
echo -n "Hash (hex):      "
xxd -p -c 64 "${hash_step0}"
echo "----------------------"

#020b68
# Step 1: RSA sign the hash with your private key
echo "Signing the raw %hash_step0% with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -digest sha512 -inkey "$PRIVATE_KEY" -rawin -in "${hash_step0}" -out "${step1}"
# Step 1a: Verify will check signature (020b68)
echo "Verifying signature, using original hash and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -digest sha512 -pubin -inkey "$PUBLIC_KEY" -rawin -in "${hash_step0}" -sigfile "${step1}"
# Step 1b: Print the signature (in hex format)
echo "Signature1 (hex):"
xxd -p -c 64 "${step1}" # 020b68
# Step 1c: Verify and recover the signature with the public key
echo "VerifyRecovering the original hash using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${step1}" -out "${step1d}" -hexdump
# Step 1d: Display the recovered hash in hex format (check first if -s is file non empty)
if [ -s "$step1d" ]; then
    echo "Recovered Hash (hex):"
#    xxd -p -c 64 "${step1d}"
    cat "${step1d}"
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s "${hash_step0}" "${step1d}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi
#Validates but Does not match, we can do it ourselves
openssl dgst -sha512 -sign  "$PRIVATE_KEY" -out "${hash_step0}.sig" "${INPUT_FILE}"
openssl dgst -sha512 -verify "$PUBLIC_KEY" -signature "${hash_step0}.sig" "${INPUT_FILE}"
# Verified OK
echo "----------------------" #020b68
#Verifies but Does not match

#3af28d
# step 2: RSA sign the Message with your private key
echo "Signing the raw Message %INPUT_FILE% with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -digest sha512 -inkey "$PRIVATE_KEY" -rawin -in "${INPUT_FILE}" -out "${step2}"
# step 2a: Verify will check signature (3afd28)
echo "Verifying signature, using original message and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -digest sha512 -pubin -inkey "$PUBLIC_KEY" -rawin -in "${INPUT_FILE}" -sigfile "${step2}"
# step 2b: Print the signature (in hex format)
echo "Signature2 (hex):"
xxd -p -c 64 "${step2}"     # 3afd28
# Step 2c: Verify and recover the signature with the public key
echo "VerifyRecovering the original file using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${step2}" -out "${step2d}" -hexdump
# step 2d: Display the recovered message in hex format (check first if -s is file non empty)
if [ -s "$step2d" ]; then
    echo "Recovered Hash (hex):"
#    xxd -p -c 64 "${step2d}"
    cat "${step2d}"
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s "${INPUT_FILE}" "${step2d}"; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi
#Validates but Does not match, we can do it ourselves
openssl dgst -sha512 -sign  "$PRIVATE_KEY" -out "${INPUT_FILE}.sig" "${INPUT_FILE}"
openssl dgst -sha512 -verify "$PUBLIC_KEY" -signature "${INPUT_FILE}.sig" "${INPUT_FILE}"
# Verified OK
echo "----------------------" #3af28d

#12d507
srcf="${hash_step0}"
sigf="${step3}"
msgf="${step3d}"
# Step 3: RSA sign the hash with your private key
echo "Signing the Hash %hash_step0% with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -in $srcf -out $sigf
# Step 3a: Verify will check signature (12d507)
echo "Verifying signature, using original hash and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -pubin -inkey "$PUBLIC_KEY" -in $srcf -sigfile $sigf
# Step 3b: Print the signature (in hex format)
echo "Signature3 (hex):"
xxd -p -c 64 "${step3}"     # 12d507
# Step 3c: Verify and recover the signature with the public key
echo "VerifyRecovering the original hash using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in $sigf -out $msgf
# Step 3d: Display the recovered hash in hex format (check first if -s is file non empty)
if [ -s $msgf ]; then
    echo "Recovered Hash (hex):"
    xxd -p -c 64 $msgf
    #echo "Comparing recovered hash with the original hash..."
    if cmp -s $srcf $msgf; then
        echo "The recovered hash MATCHES the original hash!"
    else
        echo "The recovered hash does NOT match the original hash..."
    fi
fi
#Matches 7a296f
echo "-----------Valid-----------" #12d507

#48f348
# step 4: RSA sign the Message with your private key
echo "Signing the Message %INPUT_FILE% with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -in "${INPUT_FILE}" -out "${step4}"
# step 4a: Verify will check signature (48f348)
echo "Verifying signature, using original file and RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verify -pubin -inkey "$PUBLIC_KEY" -in "${INPUT_FILE}" -sigfile "${step4}"
# step 4b: Print the signature (in hex format)
echo "Signature4 (hex):"
xxd -p -c 64 "${step4}"     # 48f348
# Step 4c: Verify and recover the signature with the public key
echo "VerifyRecovering the original file using the RSA public key: $PUBLIC_KEY"
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "${step4}" -out "${step4d}"
# step 4d: Display the recovered message in hex format (check first if -s is file non empty)
if [ -s "$step4d" ]; then
    echo "Recovered (hex):"
    xxd -p -c 64 "${step4d}"
    #cat "${step4d}"
    #echo "Comparing recovered message with the original ..."
    if cmp -s "${INPUT_FILE}" "${step4d}"; then
        echo "The recovered message MATCHES the original!"
    else
        echo "The recovered does NOT match the original..."
    fi
fi
#Matches 410a
echo "-----------Valid-----------" #48f348


# Clean up?
#rm "${hash_step0}" "${step3}" "${step1}" "${step3d}"
#rm ${INPUT_FILE}.*
