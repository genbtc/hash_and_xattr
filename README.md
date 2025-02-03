# hash and xattr, v0.3.1
# IMA Signs files, compatible with IMA.
Open a directory, scan for a list of files, hash them with SHA512, write a private key signed signature 
to the linux filesystem xattrs, as security.ima - or as fallback - user.ima.

## New Rust Program - Feb 2025

## Project Dir Structure:
src/
```
main.rs     -	main() IMA sign files (like imafix2)
find_xattr.rs	-	llistxattr wrapper to list/get xattrs
pathwalk.rs	-	Directory Traversal, STDIN support, input -f Filelist.txt of files
set_ima_xattr.rs - 	logic to set IMA xattr security.ima/user.ima
IMAhashAlgorithm.rs - equivalent of imaevm.h from ima-evm-utils, struct defs
lib.rs      -   Lib.Rs Crate Module declarations (these files)
keyid.rs	-	Extract Subject Key ID from X509 Cert (for IMA header)
hash_file.rs	-	SHA-512 hash function
format_hex.rs	-	Utility function to convert u8 bytes to ascii hex string
```
## Tests (dev):
```
generate_rsa_keypair.rs	-	Generate random public/private RSA keypair
verify_sig_hash_pub.rs	-	Verify known sig based on known key known text
```
## Rust Dependencies (Cargo.toml):
```
[dependencies]
xattr = "*"      # interacting with extended attributes
openssl = "*"  # private/public crypto key signing
hex = "*"        # for hex decode/encode
atty = "*"        # Add atty to check if stdin is connected (pathwalk)
rayon = "*"      # parallel processing iter
walkdir = "*"    # Directory traversal
```
