#!/bin/bash

# Variables for private key / public key
PRIVATE_KEY="/home/genr8eofl/signing_key.priv" #contents: -----BEGIN PRIVATE KEY----- #
#PUBLIC_KEY="/home/genr8eofl/signing_key.priv" # tried to reuse it as public derived but usually failed
 #Public Key operation error
 #40A7FCD8DC660000:error:0200008A:rsa routines:RSA_padding_check_PKCS1_type_1:invalid padding:../openssl-3.0.15/crypto/rsa/rsa_pk1.c:75:
 #40A7FCD8DC660000:error:02000072:rsa routines:rsa_ossl_public_decrypt:padding check failed:../openssl-3.0.15/crypto/rsa/rsa_ossl.c:598:
 #40A7FCD8DC660000:error:1C880004:Provider routines:rsa_verify_recover:RSA lib:../openssl-3.0.15/providers/implementations/signature/rsa_sig.c:745:
#PUBLIC_KEY="/home/genr8eofl/signing_key.priv.bak" #contents: -----BEGIN PRIVATE KEY----- +  -----BEGIN CERTIFICATE-----
  #doesnt work with pkeyutl -verifyrecover -inkey "$PUBLIC_KEY"
#PUBLIC_KEY="/home/genr8eofl/signing_key.pem"     #contents: -----BEGIN CERTIFICATE-----
 #Could not read public key from /home/genr8eofl/signing_key.pem
  #pkeyutl: Error initializing context
 #works with -certin but #Public Key operation error
  #40B79B1914600000:error:0200008A:rsa routines:RSA_padding_check_PKCS1_type_1:invalid padding:../openssl-3.0.15/crypto/rsa/rsa_pk1.c:75:
  #40B79B1914600000:error:02000072:rsa routines:rsa_ossl_public_decrypt:padding check failed:../openssl-3.0.15/crypto/rsa/rsa_ossl.c:598:
  #40B79B1914600000:error:1C880004:Provider routines:rsa_verify_recover:RSA lib:../openssl-3.0.15/providers/implementations/signature/rsa_sig.c:745:
  #after we know it works, this file now errors:
 #Could not open file or uri for loading public key from /home/genr8eofl/signing_key.pem
 #40A7F5B1A7690000:error:16000069:STORE routines:ossl_store_get0_loader_int:unregistered scheme:../openssl-3.0.15/crypto/store/store_register.c:237:scheme=file
 #40A7F5B1A7690000:error:80000002:system library:file_open:No such file or directory:../openssl-3.0.15/providers/implementations/storemgmt/file_store.c:267:calling stat(/home/genr8eofl/signing_key.pem)
PUBLIC_KEY="/home/genr8eofl/derived_public_key.pem"  #contents: -----BEGIN PUBLIC KEY-----
#(works with -verify ok)
#NOW WORKS with verifyrecover!
#(doesnt with -verifyrecover) #Public Key operation error
 #400734C75E660000:error:0200008A:rsa routines:RSA_padding_check_PKCS1_type_1:invalid padding:../openssl-3.0.15/crypto/rsa/rsa_pk1.c:75:
 #400734C75E660000:error:02000072:rsa routines:rsa_ossl_public_decrypt:padding check failed:../openssl-3.0.15/crypto/rsa/rsa_ossl.c:598:
 #400734C75E660000:error:1C880004:Provider routines:rsa_verify_recover:RSA lib:../openssl-3.0.15/providers/implementations/signature/rsa_sig.c:745:
#PUBLIC_KEY="/home/genr8eofl/signing_key.x509" # X509 encoded file - Certificate, Version=3
 #after we know it works, this file now errors:
 #Could not open file or uri for loading public key from /home/genr8eofl/signing_key.x509
 #40E71D3D76650000:error:16000069:STORE routines:ossl_store_get0_loader_int:unregistered scheme:../openssl-3.0.15/crypto/store/store_register.c:237:scheme=file
 #40E71D3D76650000:error:80000002:system library:file_open:No such file or directory:../openssl-3.0.15/providers/implementations/storemgmt/file_store.c:267:calling stat(/home/genr8eofl/signing_key.x509)

# Variables for files (and tmp)
INPUT_FILE="testA"
hash_step1a="$INPUT_FILE.sha512"
dgst_step1a="$INPUT_FILE.dgst"
hashstr_step1a="$INPUT_FILE.hash"
sig_step2="$INPUT_FILE.signature.bin"
sig_step2_raw="$INPUT_FILE.signature.raw"
step4="$INPUT_FILE.recovered_hash.bin"

# Step 1: Generate SHA-512 hash of the file
echo "Hashing file: $INPUT_FILE"
openssl dgst -sha512 -binary "$INPUT_FILE" > "${hash_step1a}"
openssl dgst -sha512         "$INPUT_FILE" > "${dgst_step1a}"

# Step 1a: Print the hash (in hex format)
echo "Hash (hex):"
xxd -p -c 64 "${hash_step1a}"

# Step 2: RSA sign the hash with your private key
echo "Signing the hash with RSA private key: $PRIVATE_KEY"
openssl pkeyutl -sign -digest sha512 -inkey "$PRIVATE_KEY" -rawin -in "${hash_step1a}" -out "${sig_step2_raw}"
openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -in "${hash_step1a}" -out "${sig_step2}"

# Step 3: Print the signature (in hex format)
echo "Signature (hex):"
#xxd -p -c 64 "${sig_step2}"    # 12d507
xxd -p -c 64 "${sig_step2_raw}" # 020b68

# Step 4: Verify and recover the signature with the public key (doesnt)
echo "VerifyRecovering the original hash using the RSA public key: $PUBLIC_KEY"
#openssl pkeyutl -verifyrecover -inkey "$PUBLIC_KEY" -in "${sig_step2}" -out "${step4}"
#openssl pkeyutl -verifyrecover -inkey "$PUBLIC_KEY" -in "${hash_step1a}" -out "${step4}" -hexdump
#openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -sigfile "${sig_step2}" -out "${step4}"
#pkeyutl: Signature file specified for non verify
#doesnt
#openssl pkeyutl -verifyrecover -inkey "$PRIVATE_KEY" -in "${hash_step1a}" -out "${step4}" #writes 0 byte file
#works but recovers this
openssl pkeyutl -verifyrecover -pubin -inkey "$PUBLIC_KEY" -in "$sig_step2" -out "${step4}"
#3051300d060960864801650304020305000440803305d4248ff306420053d133d217339f8dafcd96b70e1e6e8f56115f12e130edd2cea1e073fda86f00995511
#d50698737e7eb895096533a8b0231c15d88907             #somehow this was emitted

# Step 4a: (works) will recover the hash but the sig becomes 12d507
echo "Verifying the original hash using the RSA public key: $PUBLIC_KEY"
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

# Clean up
#rm "${hash_step1a}" "${sig_step2}" "${sig_step2_raw}" "${step4}"
